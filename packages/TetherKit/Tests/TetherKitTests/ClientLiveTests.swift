#if os(macOS)
    import CryptoKit
    import Foundation
    import Testing
    @testable import TetherKit

    private actor FixtureIdentityPersistence: TetherIdentityPersistence {
        private var values: [String: Data] = [:]
        func load(appID: String) -> Data? {
            values[appID]
        }

        func save(_ privateKey: Data, appID: String) {
            values[appID] = privateKey
        }
    }

    private actor LiveMetadataFixture: TetherHostMetadataPersistence {
        func name(appID _: String, hostKey _: Data) -> String? {
            nil
        }

        func setName(_: String, appID _: String, hostKey _: Data) {}
    }

    private actor FixturePeerPersistence: TetherPeerPersistence {
        private var values: [String: Data] = [:]
        var events: [Bool] = []
        var refuseCreate = false
        var refuseAfterCreate = false
        func setRefuseAfterCreate() {
            refuseAfterCreate = true
        }

        func setRefuseCreate() {
            refuseCreate = true
        }

        private func key(_ appID: String, _ hostKey: Data) -> String {
            appID + "|" + hostKey.base64EncodedString()
        }

        func list(appID: String) -> [Data] {
            values.filter { $0.key.hasPrefix(appID + "|") }.map(\.value)
        }

        func load(appID: String, hostKey: Data) -> Data? {
            values[key(appID, hostKey)]
        }

        func save(_ value: Data, appID: String, hostKey: Data, createOnly: Bool) throws {
            if createOnly, refuseCreate {
                throw TetherError.keychain(-1)
            }
            let id = key(appID, hostKey)
            if createOnly, values[id] != nil {
                throw TetherClientError.pairingExists
            }
            values[id] = value
            try events.append(JSONDecoder().decode(TetherPeerRecord.self, from: value).confirmed)
            if createOnly, refuseAfterCreate {
                throw TetherError.keychain(-2)
            }
        }

        func replaceConfirmed(_ value: Data, appID: String, hostKey: Data, expectedPairingID: UUID) throws {
            let id = key(appID, hostKey)
            guard let current = values[id],
                  let record = try? JSONDecoder().decode(TetherPeerRecord.self, from: current),
                  record.confirmed, record.pairingID == expectedPairingID else { throw TetherClientError.identityMismatch }
            values[id] = value
        }

        func removeConfirmed(appID: String, hostKey: Data, pairingID: UUID) throws {
            let id = key(appID, hostKey)
            guard let value = values[id],
                  let record = try? JSONDecoder().decode(TetherPeerRecord.self, from: value),
                  record.confirmed, record.pairingID == pairingID else { throw TetherClientError.identityMismatch }
            values.removeValue(forKey: id)
        }

        func discardPending(appID: String, hostKey: Data, pairingID: UUID) throws {
            let id = key(appID, hostKey)
            guard let value = values[id],
                  let record = try? JSONDecoder().decode(TetherPeerRecord.self, from: value),
                  !record.confirmed, record.pairingID == pairingID
            else {
                throw TetherClientError.pairingExists
            }
            values.removeValue(forKey: id)
        }
    }

    private struct LiveFixture: Decodable {
        let appID: String, relayURL: URL, hostID: String, code: String, binary: String, hostConfig: String
        let directPort: UInt16
        let ownerPort: UInt16
        let otherOwnerPort: UInt16
        let apiEchoPort: UInt16
        func command(_ arguments: [String]) throws -> Data {
            let process = Process(); process.executableURL = URL(fileURLWithPath: binary)
            process.arguments = arguments; let pipe = Pipe(); process.standardOutput = pipe; process.standardError = FileHandle.nullDevice
            try process.run(); let output = pipe.fileHandleForReading.readDataToEndOfFile(); process.waitUntilExit()
            guard process.terminationStatus == 0 else { throw TetherClientError.invalidProtocol }
            return output
        }

        func nextCode() throws -> String {
            let result = try command(["host", "pair-code", "--config", hostConfig])
            guard let text = String(data: result, encoding: .utf8)?.trimmingCharacters(in: .whitespacesAndNewlines), text.count == 8 else {
                throw TetherClientError.invalidProtocol
            }
            return text
        }

        func deviceCount() throws -> Int {
            let data = try command(["host", "list", "--config", hostConfig])
            guard let values = try JSONSerialization.jsonObject(with: data) as? [[String: Any]] else {
                throw TetherClientError.invalidProtocol
            }
            return values.count
        }
    }

    @Suite("Swift client interoperates with real Rust host and relay")
    struct ClientLiveTests {
        @Test(.enabled(if: ProcessInfo.processInfo.environment["TETHER_SWIFT_LIVE_FIXTURE"] != nil))
        func fullClientFlow() async throws {
            let path = try #require(ProcessInfo.processInfo.environment["TETHER_SWIFT_LIVE_FIXTURE"])
            let fixture = try JSONDecoder().decode(LiveFixture.self, from: Data(contentsOf: URL(fileURLWithPath: path)))
            let cloud = TetherRoute.cloud(relayURL: fixture.relayURL, hostID: fixture.hostID)
            let refusedStore = FixturePeerPersistence(); await refusedStore.setRefuseCreate()
            let refused = try TetherClient(appID: fixture.appID, identities: TetherIdentityStore(persistence: FixtureIdentityPersistence()),
                                           peers: TetherPeerStore(persistence: refusedStore), allowInsecureLoopbackForTesting: true)
            do { _ = try await refused.pair(route: cloud, code: fixture.code); Issue.record("a refused pending save was acknowledged") }
            catch TetherError.keychain {}
            #expect(try fixture.deviceCount() == 0, "the host must not commit before durable pending storage")

            // A write can complete durably yet report failure: no ack was sent, so this pending
            // record cannot recover host trust and must be explicitly abandoned before a fresh code.
            let uncertainStore = FixturePeerPersistence()
            await uncertainStore.setRefuseAfterCreate()
            let uncertain = try TetherClient(appID: fixture.appID,
                                             identities: TetherIdentityStore(persistence: FixtureIdentityPersistence()),
                                             peers: TetherPeerStore(persistence: uncertainStore), allowInsecureLoopbackForTesting: true)
            do { _ = try await uncertain.pair(route: cloud, code: fixture.nextCode())
                Issue.record("an uncertain pending write was acknowledged")
            } catch TetherError.keychain {}
            let pending = try #require(try await uncertain.records().first)
            #expect(!pending.confirmed)
            #expect(try fixture.deviceCount() == 0)
            do { _ = try await uncertain.recover(pending); Issue.record("an unacknowledged peer recovered trust") }
            catch {}
            let otherApp = try TetherClient(appID: "app.other", peers: TetherPeerStore(persistence: uncertainStore))
            do { try await otherApp.discardPendingPairing(pending); Issue.record("another app discarded the pending peer") }
            catch TetherError.invalidScope {}
            #expect(try await uncertain.records().count == 1)
            try await uncertain.discardPendingPairing(pending)
            #expect(try await uncertain.records().isEmpty)

            let persistence = FixturePeerPersistence()
            let client = try TetherClient(appID: fixture.appID, identities: TetherIdentityStore(persistence: FixtureIdentityPersistence()),
                                          peers: TetherPeerStore(persistence: persistence), allowInsecureLoopbackForTesting: true)
            var record = try await client.pair(route: cloud, code: fixture.nextCode())
            #expect(record.confirmed)
            #expect(await persistence.events == [false, true])
            #expect(try fixture.deviceCount() == 1)
            try await echo(client: client, record: record)
            try await bulkEcho(client: client, record: record)
            var streams: [TetherServiceStream] = []
            for _ in 0 ..< 8 {
                try streams.append(await client.openService("tcp", kind: .tcp, peer: record))
            }
            do { _ = try await client.openService("tcp", kind: .tcp, peer: record)
                Issue.record("the SDK exceeded its stream limit")
            } catch TetherClientError.streamLimit {}
            for stream in streams {
                await stream.close()
            }
            streams.removeAll()
            let afterClose = try await client.openService("tcp", kind: .tcp, peer: record)
            await afterClose.close()
            do { try await client.discardPendingPairing(record); Issue.record("confirmed trust was discarded") }
            catch TetherClientError.pairingExists {}
            #expect(try await client.records().count == 1)
            let manager = try await TetherConnectionStore(client: client, metadata: LiveMetadataFixture())
            try await manager.load()
            let managedID = record.hostKey.base64EncodedString()
            var managed: [TetherServiceStream] = []
            for _ in 0 ..< 6 {
                try managed.append(await manager.openService("tcp", kind: .tcp, hostID: managedID))
            }
            do { _ = try await manager.openService("tcp", kind: .tcp, hostID: managedID)
                Issue.record("managed streams consumed the reserved control slots")
            } catch TetherClientError.streamLimit {}
            #expect(try await client.status(record).services.count == 2)
            await managed.removeFirst().close()
            try managed.append(await manager.openService("tcp", kind: .tcp, hostID: managedID))
            for stream in managed {
                await stream.close()
            }
            await manager.stopMonitoring()
            let priorGeneration = record.pairingID
            try await manager.changeRoute(hostID: managedID, to: .privateNetwork(host: "127.0.0.1", port: fixture.directPort))
            record = try #require(try await client.records().first)
            #expect(record.pairingID != priorGeneration)
            #expect(try await client.status(record).services.count == 2)

            let directClient = try TetherClient(appID: fixture.appID, identities: TetherIdentityStore(persistence: FixtureIdentityPersistence()),
                                                peers: TetherPeerStore(persistence: FixturePeerPersistence()))
            let code = try fixture.nextCode()
            let wrong = (code.first == "0" ? "1" : "0") + String(code.dropFirst())
            let direct = TetherRoute.privateNetwork(host: "127.0.0.1", port: fixture.directPort)
            do { _ = try await directClient.pair(route: direct, code: wrong); Issue.record("wrong code was accepted") }
            catch {}
            let directRecord = try await directClient.pair(route: direct, code: code)
            try await echo(client: directClient, record: directRecord)
            try await bulkEcho(client: directClient, record: directRecord)
            if ProcessInfo.processInfo.environment["TETHER_SWIFT_MEDIA_LIVE"] == "1" {
                try await nativeMedia(client: directClient, record: directRecord)
            }
            #expect(try fixture.deviceCount() == 2)
            var firstBusy: [TetherServiceStream] = [], secondBusy: [TetherServiceStream] = []
            for _ in 0 ..< 4 {
                try firstBusy.append(await client.openService("tcp", kind: .tcp, peer: record))
                try secondBusy.append(await directClient.openService("tcp", kind: .tcp, peer: directRecord))
            }
            do { _ = try await client.openService("tcp", kind: .tcp, peer: record)
                Issue.record("host admitted a ninth data stream")
            } catch TetherClientError.hostCapacity {}
            let status = try await client.status(record)
            #expect(Set(status.services.map(\.id)) == ["tcp", "udp"])
            #expect(try await directClient.status(directRecord).services.count == 2)
            // A successful leave removes only this device at both ends.
            try await client.leave(record)
            #expect(try await client.records().isEmpty)
            #expect(try fixture.deviceCount() == 1)
            #expect(try await directClient.status(directRecord).services.count == 2)
            let surviving = Data("other peer remains usable after busy-host leave".utf8)
            #expect(try await roundTrip(secondBusy[0], payload: surviving) == surviving)
            for stream in firstBusy + secondBusy {
                await stream.close()
            }
            let device = SHA256.hash(data: directRecord.clientKey).map { String(format: "%02x", $0) }.joined()
            _ = try fixture.command(["host", "revoke", "--config", fixture.hostConfig, "--device", device])
            do { _ = try await directClient.status(directRecord); Issue.record("revoked peer reported online") }
            catch TetherClientError.peerRevoked {}
            #expect(try await directClient.records() == [directRecord], "remote revocation must not reset local trust")
            _ = try await directClient.forgetLocally(directRecord)
            #expect(try await directClient.records().isEmpty)
        }

        @Test(.enabled(if: ProcessInfo.processInfo.environment["TETHER_SWIFT_LIVE_FIXTURE"] != nil))
        @MainActor func managedMacHostFlow() async throws {
            let path = try #require(ProcessInfo.processInfo.environment["TETHER_SWIFT_LIVE_FIXTURE"])
            let fixture = try JSONDecoder().decode(LiveFixture.self, from: Data(contentsOf: URL(fileURLWithPath: path)))
            let stage = FileManager.default.temporaryDirectory.appendingPathComponent("tether-mac-host-" + UUID().uuidString)
            try FileManager.default.createDirectory(at: stage, withIntermediateDirectories: false,
                                                    attributes: [.posixPermissions: 0o700])
            defer { try? FileManager.default.removeItem(at: stage) }
            let app = "app.tether.mac-host-fixture"
            let controller = try TetherHostController(helperURL: URL(fileURLWithPath: fixture.binary),
                                                      configurationURL: stage.appendingPathComponent("host.json"), appID: app)
            let other = try TetherHostController(helperURL: URL(fileURLWithPath: fixture.binary),
                                                 configurationURL: stage.appendingPathComponent("other.json"), appID: app)
            let client = try TetherClient(appID: app,
                                          identities: TetherIdentityStore(persistence: FixtureIdentityPersistence()),
                                          peers: TetherPeerStore(persistence: FixturePeerPersistence()))
            do {
                try await controller.initialize(services: [TetherHostServiceProfile(id: "api", kind: .tcp, port: fixture.apiEchoPort)])
                try await controller.start(route: .privateNetwork(address: "127.0.0.1", port: fixture.ownerPort))
                let deadline = ContinuousClock.now.advanced(by: .seconds(10))
                while controller.state == .starting {
                    guard ContinuousClock.now < deadline else { throw TetherClientError.timeout }
                    try await Task.sleep(for: .milliseconds(20))
                }
                #expect(controller.state == .listening(address: "127.0.0.1:\(fixture.ownerPort)"))
                try await controller.openPairingWindow()
                let code = try #require(controller.pairingCode)
                let record = try await client.pair(route: .privateNetwork(host: "127.0.0.1", port: fixture.ownerPort), code: code)
                #expect(try await client.status(record).services == [TetherHostService(id: "api", kind: .tcp)])
                try await other.initialize(services: [TetherHostServiceProfile(id: "api", kind: .tcp, port: fixture.apiEchoPort)])
                try await other.start(route: .privateNetwork(address: "127.0.0.1", port: fixture.otherOwnerPort))
                let otherDeadline = ContinuousClock.now.advanced(by: .seconds(10))
                while other.state == .starting {
                    guard ContinuousClock.now < otherDeadline else { throw TetherClientError.timeout }
                    try await Task.sleep(for: .milliseconds(20))
                }
                do {
                    _ = try await client.updateRoute(record, to: .privateNetwork(host: "127.0.0.1", port: fixture.otherOwnerPort))
                    Issue.record("a candidate route substituted another host's identity")
                } catch TetherClientError.identityMismatch {}
                #expect(try await client.records() == [record], "substitution must preserve the old route and pins")
                try await other.openPairingWindow()
                let otherCode = try #require(other.pairingCode)
                let otherRecord = try await client.pair(route: .privateNetwork(host: "127.0.0.1", port: fixture.otherOwnerPort), code: otherCode)
                #expect(record.hostKey != otherRecord.hostKey && record.clientKey == otherRecord.clientKey)
                #expect(try await client.records().count == 2)
                let manager = try TetherConnectionStore(client: client, metadata: LiveMetadataFixture())
                try await manager.load()
                let firstID = record.hostKey.base64EncodedString(), secondID = otherRecord.hostKey.base64EncodedString()
                manager.connect(hostID: firstID); manager.connect(hostID: secondID)
                let connectedDeadline = ContinuousClock.now.advanced(by: .seconds(10))
                while manager.hosts.filter({ $0.state == .connected }).count != 2 {
                    guard ContinuousClock.now < connectedDeadline else { throw TetherClientError.timeout }
                    try await Task.sleep(for: .milliseconds(20))
                }
                manager.selectedHostID = firstID; manager.selectedHostID = secondID
                let firstStream = try await manager.openService("api", kind: .tcp, hostID: firstID)
                let secondStream = try await manager.openService("api", kind: .tcp, hostID: secondID)
                let firstPayload = Data("first host independent stream".utf8)
                let secondPayload = Data("second host independent stream".utf8)
                async let firstReply = roundTrip(firstStream, payload: firstPayload)
                async let secondReply = roundTrip(secondStream, payload: secondPayload)
                let replies = try await (firstReply, secondReply)
                #expect(replies.0 == firstPayload)
                #expect(replies.1 == secondPayload)
                try await other.refreshClients()
                #expect(other.clients.count == 1)
                try await controller.refreshClients()
                let device = try #require(controller.clients.first?.id)
                #expect(controller.clients.count == 1)
                try await controller.revoke(clientID: device)
                #expect(controller.clients.isEmpty)
                do { _ = try await client.status(record); Issue.record("owner-revoked client stayed authorized") }
                catch TetherClientError.peerRevoked {}
                #expect(try Set(await client.records().map(\.hostKey)) == Set([record.hostKey, otherRecord.hostKey]))
                await controller.stop()
                #expect(controller.state == .stopped && controller.pairingCode == nil)
                #expect(try await roundTrip(secondStream, payload: secondPayload) == secondPayload)
                #expect(try await client.status(otherRecord).services.count == 1)
                #expect(manager.selectedHostID == secondID)
                #expect(manager.hosts.first(where: { $0.id == secondID })?.state == .connected)
                await firstStream.close(); await secondStream.close(); manager.stopMonitoring()
                await other.stop()
            } catch { await other.stop(); await controller.stop(); throw error }
        }

        private func bulkEcho(client: TetherClient, record: TetherPeerRecord) async throws {
            let stream = try await client.openService("tcp", kind: .tcp, peer: record)
            var payload = Data()
            for block in 0 ..< 256 {
                payload.append(Data(repeating: UInt8(block), count: 16384))
            }
            let expected = payload
            do {
                let received = try await withTetherDeadline(seconds: 30) {
                    async let writing: Void = {
                        for offset in stride(from: 0, to: expected.count, by: 16384) {
                            try await stream.send(expected.subdata(in: offset ..< offset + 16384))
                        }
                        try await stream.finishSending()
                    }()
                    var bytes = Data()
                    while let chunk = try await stream.receive() {
                        guard bytes.count + chunk.count <= expected.count else { throw TetherClientError.invalidFrame }
                        bytes.append(chunk)
                    }
                    try await writing
                    return bytes
                }
                #expect(received == expected, "4 MiB simultaneous write/read changed bytes or deadlocked")
                await stream.close()
            } catch { await stream.close(); throw error }
        }

        private func nativeMedia(client: TetherClient, record: TetherPeerRecord) async throws {
            let media = try await client.openMedia("udp", peer: record)
            do {
                #expect((1 ... 1152).contains(media.maximumDatagramSize))
                let packet = Data("Swift native QUIC through the authorized fixed UDP service".utf8)
                try await media.send(packet)
                #expect(try await media.receive() == packet)
                try await media.send(Data())
                #expect(try await media.receive() == Data())
                var samples: [Double] = []
                let probe = Data(repeating: 0x5A, count: 1024)
                for _ in 0 ..< 30 {
                    let start = ContinuousClock.now
                    try await media.send(probe)
                    #expect(try await media.receive() == probe)
                    let elapsed = start.duration(to: .now).components
                    samples.append(Double(elapsed.seconds) * 1000 + Double(elapsed.attoseconds) / 1e15)
                }
                let sorted = samples.sorted()
                let rtt: [String: Any] = ["route": "private-loopback", "transport": "Swift-CABI-native-QUIC-fixed-UDP-echo",
                                          "packetBytes": 1024, "samples": samples, "paced": false,
                                          "medianMilliseconds": sorted[sorted.count / 2],
                                          "p95Milliseconds": sorted[Int(ceil(Double(sorted.count) * 0.95)) - 1],
                                          "minimumMilliseconds": sorted.first ?? 0, "maximumMilliseconds": sorted.last ?? 0]
                try JSONSerialization.data(withJSONObject: rtt, options: [.sortedKeys, .prettyPrinted])
                    .write(to: URL(fileURLWithPath: "/tmp/tether-swift-media-rtt.json"), options: .atomic)
                do { try await media.send(Data(repeating: 1, count: media.maximumDatagramSize + 1))
                    Issue.record("oversized native packet was fragmented or sent")
                } catch TetherClientError.invalidFrame {}
                // Cross the five-second lease TTL: success here requires the retained Noise
                // heartbeat rather than an initial QUIC handshake alone.
                try await Task.sleep(for: .seconds(6))
                try await media.send(packet)
                #expect(try await media.receive() == packet)
                let metrics = try await media.statistics()
                #expect(metrics.packetsSent >= 3 && metrics.packetsReceived >= 3)
                #expect(metrics.roundTripMilliseconds.isFinite && metrics.roundTripMilliseconds >= 0)
                await media.close()
                #expect(await media.state == .closed)
            } catch { await media.close(); throw error }
            let canceled = try await client.openMedia("udp", peer: record)
            let receive = Task { try await canceled.receive() }
            try await Task.sleep(for: .milliseconds(20)); receive.cancel()
            do { _ = try await receive.value; Issue.record("canceled native receive completed") }
            catch is CancellationError {}
            #expect(await canceled.state == .failed)
        }

        private func roundTrip(_ stream: TetherServiceStream, payload: Data) async throws -> Data {
            try await stream.send(payload)
            var received = Data()
            while received.count < payload.count {
                guard let part = try await stream.receive() else { throw TetherClientError.connectionClosed }
                received.append(part)
            }
            return received
        }

        private func echo(client: TetherClient, record: TetherPeerRecord) async throws {
            let tcp = try await client.openService("tcp", kind: .tcp, peer: record)
            let payload = Data("Swift through Rust host and relay".utf8)
            try await tcp.send(payload)
            var received = Data()
            while received.count < payload.count {
                guard let part = try await tcp.receive() else { throw TetherClientError.connectionClosed }
                received.append(part)
            }
            #expect(received == payload)
            try await tcp.finishSending()
            #expect(try await tcp.receive() == nil)
            await tcp.close()
            let udp = try await client.openReliablePacketStream("udp", peer: record)
            try await udp.send(payload)
            #expect(try await udp.receive() == payload)
            try await udp.send(Data())
            #expect(try await udp.receive() == Data(), "empty datagram must not become TCP EOF")
            await udp.close()
            do { _ = try await client.openService("undeclared", kind: .tcp, peer: record); Issue.record("undeclared service opened") }
            catch {}
        }
    }
#endif
