#if os(macOS)
    import Foundation
    import Testing
    @testable import TetherKit

    private actor NearbyIdentities: TetherIdentityPersistence {
        private var values: [String: Data] = [:]
        func load(appID: String) -> Data? { values[appID] }
        func save(_ privateKey: Data, appID: String) { values[appID] = privateKey }
    }

    private actor NearbyPeers: TetherPeerPersistence {
        private var values: [String: Data] = [:]
        private func key(_ appID: String, _ hostKey: Data) -> String { appID + "|" + hostKey.base64EncodedString() }
        func list(appID: String) -> [Data] { values.filter { $0.key.hasPrefix(appID + "|") }.map(\.value) }
        func load(appID: String, hostKey: Data) -> Data? { values[key(appID, hostKey)] }
        func save(_ value: Data, appID: String, hostKey: Data, createOnly: Bool) throws {
            let id = key(appID, hostKey)
            if createOnly, values[id] != nil { throw TetherClientError.pairingExists }
            values[id] = value
        }
        func discardPending(appID: String, hostKey: Data, pairingID _: UUID) { values.removeValue(forKey: key(appID, hostKey)) }
    }

    private final class Answer: @unchecked Sendable {
        private let lock = NSLock()
        private var value: Bool?
        private var shown: TetherNearbyCode?
        func set(_ answer: Bool) { lock.withLock { value = answer } }
        func get() -> Bool? { lock.withLock { value } }
        func show(_ code: TetherNearbyCode) { lock.withLock { shown = code } }
        var code: TetherNearbyCode? { lock.withLock { shown } }
    }

    /// The Swift client against the real Rust host, driven through the Mac host controller.
    /// Run with TETHER_NEARBY_HELPER=<path to target/debug/tether>.
    @Suite("Nearby pairing against the Rust host")
    struct NearbyLiveTests {
        static var helper: String? { ProcessInfo.processInfo.environment["TETHER_NEARBY_HELPER"] }

        private static func freePort() -> UInt16 {
            let fd = socket(AF_INET, SOCK_STREAM, 0); defer { close(fd) }
            var address = sockaddr_in(); address.sin_family = sa_family_t(AF_INET); address.sin_addr.s_addr = inet_addr("127.0.0.1")
            var length = socklen_t(MemoryLayout<sockaddr_in>.size)
            _ = withUnsafePointer(to: &address) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { bind(fd, $0, length) } }
            _ = withUnsafeMutablePointer(to: &address) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { getsockname(fd, $0, &length) } }
            return UInt16(bigEndian: address.sin_port)
        }

        @MainActor private func host(_ stage: URL, app: String) async throws -> (TetherHostController, UInt16) {
            let port = Self.freePort()
            let controller = try TetherHostController(helperURL: URL(fileURLWithPath: try #require(Self.helper)),
                                                      configurationURL: stage.appendingPathComponent("host.json"), appID: app)
            try await controller.initialize(services: [TetherHostServiceProfile(id: "api", kind: .tcp, port: 9)])
            try await controller.start(route: .privateNetwork(address: "127.0.0.1", port: port))
            let deadline = ContinuousClock.now.advanced(by: .seconds(10))
            while controller.state == .starting {
                guard ContinuousClock.now < deadline else { throw TetherClientError.timeout }
                try await Task.sleep(for: .milliseconds(20))
            }
            return (controller, port)
        }

        @Test(.enabled(if: helper != nil))
        @MainActor func bothOwnersSeeOneCodeAndTrustNeedsBothApprovals() async throws {
            let stage = FileManager.default.temporaryDirectory.appendingPathComponent("tether-nearby-" + UUID().uuidString)
            try FileManager.default.createDirectory(at: stage, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
            defer { try? FileManager.default.removeItem(at: stage) }
            let app = "app.tether.nearby-fixture"
            let (controller, port) = try await host(stage, app: app)
            defer { Task { await controller.stop() } }
            let client = try TetherClient(appID: app, identities: TetherIdentityStore(persistence: NearbyIdentities()),
                                          peers: TetherPeerStore(persistence: NearbyPeers()))
            let route = TetherRoute.privateNetwork(host: "127.0.0.1", port: port)

            // The host owner declines: nothing is stored on either side.
            let declined = Answer()
            async let first = client.pairNearby(route: route, deviceName: "Field iPhone", deviceKind: "iPhone",
                                                onCode: { declined.show($0) }, decision: { declined.get() })
            var hostCode: TetherNearbyCode?
            for _ in 0 ..< 200 where hostCode == nil {
                if let request = controller.nearbyRequests.first, declined.code != nil {
                    hostCode = request.code
                    #expect(request.name == "Field iPhone")
                    try await controller.decideNearby(request, approve: false)
                    declined.set(true)
                }
                try await Task.sleep(for: .milliseconds(25))
            }
            #expect(try await first == .declined)
            #expect(hostCode == declined.code)
            #expect(try await client.records().isEmpty)

            // Both approve, the device first: the same code, then a confirmed record on each side.
            let approved = Answer()
            async let second = client.pairNearby(route: route, deviceName: "Field iPhone", deviceKind: "iPhone",
                                                 onCode: { approved.show($0) }, decision: { approved.get() })
            var decided = false
            var shownAt: ContinuousClock.Instant?
            for _ in 0 ..< 400 where !decided {
                // The device's owner reads the code, then taps Approve a moment later.
                if approved.code != nil, shownAt == nil { shownAt = .now }
                if let shownAt, ContinuousClock.now > shownAt.advanced(by: .milliseconds(1300)) { approved.set(true) }
                if let request = controller.nearbyRequests.first, request.deviceApproved {
                    #expect(request.code == approved.code)
                    try await controller.decideNearby(request, approve: true)
                    decided = true
                }
                try await Task.sleep(for: .milliseconds(25))
            }
            guard case let .paired(record) = try await second else { Issue.record("expected a pairing"); return }
            #expect(record.confirmed)
            #expect(try await client.status(record).services == [TetherHostService(id: "api", kind: .tcp)])
            try await controller.refreshClients()
            #expect(controller.clients.count == 1)

            // A decision that already reads "approve" before the code appears never counts.
            let fresh = try TetherClient(appID: app, identities: TetherIdentityStore(persistence: NearbyIdentities()),
                                         peers: TetherPeerStore(persistence: NearbyPeers()))
            let preset = Task { try await fresh.pairNearby(route: route, deviceName: "Preset", deviceKind: "iPhone",
                                                           onCode: { _ in }, decision: { true }) }
            for _ in 0 ..< 200 {
                if let request = controller.nearbyRequests.first(where: { $0.name == "Preset" }) {
                    try await controller.decideNearby(request, approve: true); break
                }
                try await Task.sleep(for: .milliseconds(25))
            }
            try await Task.sleep(for: .seconds(3))
            preset.cancel()
            // Cancelling declines; the call ends declined or with the cancellation, never paired.
            if case .paired? = try? await preset.value { Issue.record("a pre-set approval paired a device") }
            #expect(try await fresh.records().isEmpty)
        }
    }
#endif
