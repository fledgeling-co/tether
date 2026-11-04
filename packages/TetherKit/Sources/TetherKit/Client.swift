import Foundation

public enum TetherServiceKind: String, Codable, Sendable { case tcp, udp }

private struct ClientControlHeader: Decodable {
    let v: Int
    let type: String
    let code: String?
}

actor ClientSession: MediaLeaseControl {
    private let carrier: any TetherCarrier
    private let cipher: TetherSecureTransport
    nonisolated let peer: Data
    nonisolated let binding: Data
    private var sending = false
    private var receiving = false
    private var closed = false
    private init(carrier: any TetherCarrier, cipher: TetherSecureTransport, peer: Data, binding: Data) {
        self.carrier = carrier; self.cipher = cipher; self.peer = peer; self.binding = binding
    }

    static func connect(route: TetherRoute, identity: TetherIdentity, appID: String,
                        pin: Data?, allowLoopback: Bool) async throws -> ClientSession
    {
        let carrier = try await route.connect(appID: appID, allowLoopback: allowLoopback)
        do {
            let handshake = try TetherNoise(identity: identity, appID: appID, role: .client)
            try await carrier.send(handshake.write())
            try await handshake.read(withTetherDeadline { try await carrier.receive() })
            guard let peer = await handshake.metadata?.remoteStatic, peer.count == 32 else {
                throw TetherClientError.invalidProtocol
            }
            // Refuse a substituted host before message three discloses the client static key.
            guard pin == nil || pin == peer else { throw TetherClientError.identityMismatch }
            try await carrier.send(handshake.write())
            let cipher = try await handshake.finish()
            return ClientSession(carrier: carrier, cipher: cipher, peer: peer, binding: cipher.metadata.binding)
        } catch { await carrier.close(); throw error }
    }

    func send(_ bytes: Data) async throws {
        guard !closed else { throw TetherError.closed }
        guard !sending else { throw TetherClientError.operationInProgress }
        sending = true
        defer { sending = false }
        do { try await carrier.send(cipher.encrypt(bytes)) }
        catch { await close(); throw error }
    }

    func receive() async throws -> Data {
        guard !closed else { throw TetherError.closed }
        guard !receiving else { throw TetherClientError.operationInProgress }
        receiving = true
        defer { receiving = false }
        do { return try await cipher.decrypt(carrier.receive()) }
        catch { await close(); throw error }
    }

    func sendControl(_ value: [String: String]) async throws {
        var json: [String: Any] = value
        json["v"] = 1
        let bytes = try JSONSerialization.data(withJSONObject: json)
        guard bytes.count <= 4096 else { throw TetherClientError.invalidFrame }
        try await send(bytes)
    }

    func controlData(expecting type: String) async throws -> Data {
        let bytes = try await withTetherDeadline { try await self.receive() }
        guard bytes.count <= 4096 else { throw TetherClientError.invalidProtocol }
        let header = try JSONDecoder().decode(ClientControlHeader.self, from: bytes)
        guard header.v == 1 else { throw TetherClientError.invalidProtocol }
        if header.type == "error" {
            switch header.code {
            case "peer_revoked": throw TetherClientError.peerRevoked
            case "service_denied": throw TetherClientError.serviceRefused
            case "service_capacity": throw TetherClientError.hostCapacity
            case "media_unavailable": throw TetherClientError.mediaUnavailable
            default: throw TetherClientError.invalidProtocol
            }
        }
        guard header.type == type else { throw TetherClientError.invalidProtocol }
        return bytes
    }

    func control(expecting type: String) async throws -> [String: String] {
        let bytes = try await controlData(expecting: type)
        guard let json = try JSONSerialization.jsonObject(with: bytes) as? [String: Any] else {
            throw TetherClientError.invalidProtocol
        }
        return json.compactMapValues { $0 as? String }
    }

    func close() async {
        guard !closed else { return }
        closed = true
        await carrier.close()
        await cipher.close()
    }
}

/// One fixed authorized host service. Await each send/receive; one operation per direction is
/// admitted at once, bounding producer buffering while allowing simultaneous reads and writes.
public actor TetherServiceStream {
    public nonisolated let kind: TetherServiceKind
    private let session: ClientSession
    private let released: @Sendable () async -> Void
    private var sentFIN = false
    private var receivedFIN = false
    private var closed = false
    fileprivate init(kind: TetherServiceKind, session: ClientSession, released: @escaping @Sendable () async -> Void) {
        self.kind = kind; self.session = session; self.released = released
    }

    deinit {
        let session = session
        let released = released
        let needsRelease = !closed
        Task {
            if needsRelease {
                await released()
            }; await session.close()
        }
    }

    public var isClosed: Bool {
        closed
    }

    public func send(_ bytes: Data) async throws {
        guard !closed, !sentFIN else { throw TetherError.closed }
        guard bytes.count <= 16384 else { throw TetherClientError.invalidFrame }
        if kind == .tcp, bytes.isEmpty {
            return
        }
        do { try await session.send(bytes) }
        catch { await close(); throw error }
    }

    /// TCP returns nil on authenticated half-close. UDP returns empty Data for an empty packet.
    public func receive() async throws -> Data? {
        guard !closed else { throw TetherError.closed }
        if receivedFIN {
            return nil
        }
        do {
            let bytes = try await session.receive()
            if kind == .tcp, bytes.isEmpty {
                receivedFIN = true
                if sentFIN {
                    await close()
                }
                return nil
            }
            return bytes
        } catch { await close(); throw error }
    }

    public func finishSending() async throws {
        guard kind == .tcp, !closed, !sentFIN else { throw TetherError.closed }
        sentFIN = true
        do {
            try await session.send(Data()); if receivedFIN {
                await close()
            }
        } catch { await close(); throw error }
    }

    public func close() async {
        guard !closed else { return }
        closed = true
        await released()
        await session.close()
    }
}

/// Each instance belongs to one application. The host retains all service and revocation authority.
public actor TetherClient {
    public nonisolated let appID: String
    private let identities: TetherIdentityStore
    private let peers: TetherPeerStore
    private let allowLoopback: Bool
    private var pairingBusy = false
    private var openStreams = Set<UUID>()
    public init(appID: String, identities: TetherIdentityStore = TetherIdentityStore(),
                peers: TetherPeerStore = TetherPeerStore(), allowInsecureLoopbackForTesting: Bool = false) throws
    {
        try Bridge.validateScope(appID)
        self.appID = appID; self.identities = identities; self.peers = peers
        allowLoopback = allowInsecureLoopbackForTesting
    }

    public func records() async throws -> [TetherPeerRecord] {
        try await peers.records(appID: appID)
    }

    public func pair(route: TetherRoute, code: String) async throws -> TetherPeerRecord {
        guard !pairingBusy else { throw TetherClientError.operationInProgress }
        pairingBusy = true
        defer { pairingBusy = false }
        let identity = try await identities.identity(appID: appID)
        let session = try await ClientSession.connect(route: route, identity: identity, appID: appID,
                                                      pin: nil, allowLoopback: allowLoopback)
        do {
            let exchange = try TetherPairing(role: .client, code: code, appID: appID,
                                             binding: session.binding, clientKey: identity.publicKey, hostKey: session.peer)
            try await session.sendControl(["type": "pair.start", "element": exchange.message.base64EncodedString()])
            let reply = try await session.control(expecting: "pair.reply")
            guard let element = reply["element"].flatMap({ Data(base64Encoded: $0) }),
                  let proof = reply["proof"].flatMap({ Data(base64Encoded: $0) })
            else {
                throw TetherClientError.invalidProtocol
            }
            let confirmation = try await exchange.finish(element)
            try await confirmation.verify(proof)
            try await session.sendControl(["type": "pair.confirm", "proof": confirmation.outbound.base64EncodedString()])
            _ = try await session.control(expecting: "pair.ready")
            let record = TetherPeerRecord(appID: appID, hostKey: session.peer, clientKey: identity.publicKey,
                                          route: route, confirmed: false)
            // The durable pending record precedes ack. Interrupted completion is recoverable.
            try await peers.begin(record)
            try await session.sendControl(["type": "pair.ack"])
            _ = try await session.control(expecting: "pair.done")
            let confirmed = try await peers.confirm(record)
            await session.close()
            return confirmed
        } catch { await session.close(); throw error }
    }

    /// Explicit recovery when the host never received the pending pairing's ack. Confirmed
    /// trust is never removed here; obtain a fresh owner code after discarding the pending record.
    public func discardPendingPairing(_ record: TetherPeerRecord) async throws {
        guard record.appID == appID else { throw TetherError.invalidScope }
        try await peers.discardPending(record)
    }

    public func recover(_ record: TetherPeerRecord) async throws -> TetherPeerRecord {
        let session = try await connect(record)
        do {
            try await session.sendControl(["type": "pair.status"])
            _ = try await session.control(expecting: "pair.done")
            let confirmed = try await peers.confirm(record)
            await session.close()
            return confirmed
        } catch { await session.close(); throw error }
    }

    public func openService(_ name: String, kind: TetherServiceKind,
                            peer record: TetherPeerRecord) async throws -> TetherServiceStream
    {
        try Bridge.validateScope(name)
        guard record.appID == appID else { throw TetherError.invalidScope }
        guard openStreams.count < 8 else { throw TetherClientError.streamLimit }
        let lease = UUID()
        openStreams.insert(lease)
        do {
            guard let stored = try await peers.record(appID: appID, hostKey: record.hostKey), stored.confirmed else {
                throw TetherClientError.pairingPending
            }
            guard stored == record, stored.clientKey == record.clientKey else { throw TetherClientError.identityMismatch }
            let session = try await connect(stored)
            do {
                try await session.sendControl(["type": "service.open", "service": name])
                let reply = try await session.control(expecting: "service.ready")
                guard reply["kind"] == kind.rawValue else { throw TetherClientError.serviceRefused }
                return TetherServiceStream(kind: kind, session: session) { await self.release(lease) }
            } catch { await session.close(); throw error }
        } catch { openStreams.remove(lease); throw error }
    }

    /// A fresh pinned handshake and authenticated host reply, never inferred from saved trust.
    public func status(_ record: TetherPeerRecord) async throws -> TetherHostStatus {
        guard record.confirmed else { throw TetherClientError.pairingPending }
        let session = try await connect(record)
        do {
            try await session.sendControl(["type": "host.status"])
            let data = try await session.controlData(expecting: "host.status")
            let status = try decodeStatus(data)
            await session.close()
            return status
        } catch { await session.close(); throw error }
    }

    /// Authenticate a candidate route with the existing pins before a generation-checked write.
    public func updateRoute(_ record: TetherPeerRecord, to route: TetherRoute) async throws -> TetherPeerRecord {
        guard record.appID == appID, record.confirmed,
              try await peers.record(appID: appID, hostKey: record.hostKey) == record
        else {
            throw TetherClientError.identityMismatch
        }
        let identity = try await identities.identity(appID: appID)
        guard identity.publicKey == record.clientKey else { throw TetherClientError.identityMismatch }
        let session = try await ClientSession.connect(route: route, identity: identity, appID: appID,
                                                      pin: record.hostKey, allowLoopback: allowLoopback)
        do {
            try await session.sendControl(["type": "host.status"])
            let data = try await session.controlData(expecting: "host.status")
            _ = try decodeStatus(data)
            try Task.checkCancellation()
            let replacement = try await peers.replaceRoute(record, route: route)
            await session.close()
            return replacement
        } catch { await session.close(); throw error }
    }

    /// Revoke this device durably at the host before removing its confirmed local record.
    /// Any network, identity or acknowledgement failure preserves local trust for retry.
    public func leave(_ record: TetherPeerRecord) async throws {
        guard record.confirmed else { throw TetherClientError.pairingPending }
        let session = try await connect(record)
        do {
            try await session.sendControl(["type": "peer.leave"])
            _ = try await session.control(expecting: "peer.left")
            try await peers.removeConfirmed(record)
            await session.close()
        } catch { await session.close(); throw error }
    }

    /// Explicit local deletion only. The unreachable host may still authorize this device.
    @discardableResult
    public func forgetLocally(_ record: TetherPeerRecord) async throws -> TetherLocalForgetResult {
        guard record.appID == appID else { throw TetherError.invalidScope }
        try await peers.removeConfirmed(record)
        return .localTrustRemovedHostUnchanged
    }

    /// An explicit ordered packet stream over the existing encrypted carrier. This is a separate
    /// caller choice from native QUIC; it is never selected as a fallback by openMedia.
    public func openReliablePacketStream(_ name: String, peer record: TetherPeerRecord) async throws -> TetherServiceStream {
        try await openService(name, kind: .udp, peer: record)
    }

    public func openMedia(_ name: String, peer record: TetherPeerRecord) async throws -> TetherMediaSession {
        try Bridge.validateScope(name)
        guard record.appID == appID, record.confirmed else { throw TetherError.invalidScope }
        guard case let .privateNetwork(address, _) = record.route else { throw TetherClientError.mediaUnavailable }
        guard openStreams.count < 8 else { throw TetherClientError.streamLimit }
        let lease = UUID(); openStreams.insert(lease)
        do {
            let session = try await connect(record)
            do {
                try await session.sendControl(["type": "media.open", "service": name])
                var data = try await session.controlData(expecting: "media.ready")
                defer { data.resetBytes(in: data.startIndex ..< data.endIndex) }
                let offer = try JSONDecoder().decode(MediaOffer.self, from: data)
                return try await TetherMediaSession.open(address: address, offer: offer, control: session) {
                    await self.release(lease)
                }
            } catch { await session.close(); throw error }
        } catch { openStreams.remove(lease); throw error }
    }

    private func decodeStatus(_ data: Data) throws -> TetherHostStatus {
        let status = try JSONDecoder().decode(TetherHostStatus.self, from: data)
        guard status.services.count <= 32,
              Set(status.services.map(\.id)).count == status.services.count
        else {
            throw TetherClientError.invalidProtocol
        }
        for service in status.services {
            try Bridge.validateScope(service.id)
        }
        return status
    }

    private func release(_ lease: UUID) {
        openStreams.remove(lease)
    }

    private func connect(_ record: TetherPeerRecord) async throws -> ClientSession {
        guard record.appID == appID,
              let stored = try await peers.record(appID: appID, hostKey: record.hostKey), stored == record
        else {
            throw TetherClientError.identityMismatch
        }
        let identity = try await identities.identity(appID: appID)
        guard identity.publicKey == stored.clientKey else { throw TetherClientError.identityMismatch }
        return try await ClientSession.connect(route: stored.route, identity: identity, appID: appID,
                                               pin: stored.hostKey, allowLoopback: allowLoopback)
    }
}
