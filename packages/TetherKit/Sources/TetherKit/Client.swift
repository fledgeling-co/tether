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

    /// Encodes a control record before it crosses into the session actor.
    nonisolated static func record(_ value: [String: Any]) throws -> Data {
        var json = value
        json["v"] = 1
        let bytes = try JSONSerialization.data(withJSONObject: json)
        guard bytes.count <= 4096 else { throw TetherClientError.invalidFrame }
        return bytes
    }

    /// Reads one control record for a shared flow to judge, host errors included.
    func recordData() async throws -> Data {
        let bytes = try await withTetherDeadline { try await self.receive() }
        guard bytes.count <= 4096 else { throw TetherClientError.invalidProtocol }
        return bytes
    }

    /// Encodes a record a shared flow produced; it already carries `v`.
    nonisolated static func encode(flowRecord value: [String: Any]) throws -> Data {
        let bytes = try JSONSerialization.data(withJSONObject: value)
        guard bytes.count <= 4096 else { throw TetherClientError.invalidFrame }
        return bytes
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
            let (flow, steps) = try TetherFlow.begin([
                "command": "code.begin", "app": appID, "code": code, "binding": session.binding.base64EncodedString(),
                "clientKey": identity.publicKey.base64EncodedString(), "hostKey": session.peer.base64EncodedString(),
            ])
            let outcome = try await drive(flow, steps, session: session, route: route, identity: identity)
            await session.close()
            guard case let .paired(record) = outcome else { throw TetherClientError.invalidProtocol }
            return record
        } catch { await session.close(); throw error }
    }

    /// Performs a shared flow's steps until it ends. `decision` and the code callbacks are for
    /// nearby pairing; code pairing never asks for them.
    private func drive(_ flow: TetherFlow, _ first: [TetherFlow.Step], session: ClientSession, route: TetherRoute,
                       identity: TetherIdentity, onCode: @Sendable (TetherNearbyCode) async -> Void = { _ in },
                       onHostApproved: @Sendable () async -> Void = {}, onStoring: @Sendable () async -> Void = {},
                       decision: @Sendable () async -> Bool? = { nil }) async throws -> TetherNearbyOutcome
    {
        let started = ContinuousClock.now
        func now() -> UInt64 {
            let elapsed = ContinuousClock.now - started
            return UInt64(elapsed.components.seconds) * 1000 + UInt64(elapsed.components.attoseconds / 1_000_000_000_000_000)
        }
        // Cancelling the task is a decline.
        func current() async -> Bool? { Task.isCancelled ? false : await decision() }
        var steps = first
        var pending: TetherPeerRecord?
        var confirmed: TetherPeerRecord?
        while true {
            var next: [TetherFlow.Step] = []
            for step in steps {
                switch step {
                case let .send(message): try await session.send(ClientSession.encode(flowRecord: message))
                case .receive:
                    let bytes = try await session.recordData()
                    guard let message = try JSONSerialization.jsonObject(with: bytes) as? [String: Any] else {
                        throw TetherClientError.invalidProtocol
                    }
                    next = try await flow.receive(message, decision: current(), now: now())
                case let .wait(ms):
                    try? await Task.sleep(for: .milliseconds(ms))
                    next = try await flow.tick(decision: current(), now: now())
                case let .showCode(digits):
                    guard let code = TetherNearbyCode(digits: digits) else { throw TetherClientError.invalidProtocol }
                    await onCode(code)
                    // Only now is the code on screen, so only now does its read time start.
                    next = try await flow.shown(decision: current(), now: now())
                case .hostApproved: await onHostApproved()
                case .storePending:
                    // The durable pending record precedes ack. Interrupted completion is recoverable.
                    let record = TetherPeerRecord(appID: appID, hostKey: session.peer, clientKey: identity.publicKey,
                                                  route: route, confirmed: false)
                    try await peers.begin(record)
                    pending = record
                    // From here the ack makes completion irreversible, so the UI stops offering Cancel.
                    await onStoring()
                    next = try await flow.stored(decision: current())
                case .discardPending:
                    if let pending { try await peers.discardPending(pending) }
                    pending = nil
                case .confirm:
                    guard let pending else { throw TetherClientError.pairingPending }
                    confirmed = try await peers.confirm(pending)
                case let .outcome(outcome):
                    switch outcome {
                    case "paired":
                        guard let confirmed else { throw TetherClientError.pairingPending }
                        return .paired(confirmed)
                    case "declined": return .declined
                    case "expired": return .expired
                    default: throw TetherClientError.invalidProtocol
                    }
                case let .failed(code): throw TetherClientError.from(code: code)
                }
            }
            guard !next.isEmpty else { throw TetherClientError.invalidProtocol }
            steps = next
        }
    }

    /// Pairs by comparing a code shown on both devices. `onCode` receives the code once both
    /// sides can show it; `onHostApproved` fires when the host's owner has approved; `decision`
    /// returns this device owner's answer, or nil while undecided. Trust is saved only after both
    /// owners approve. Cancelling the task declines the request.
    /// `inviteToken` is the one-time token this device issued to a computer that invited it; it
    /// is repeated to the host so the host's owner can see which request answered that invite.
    public func pairNearby(route: TetherRoute, deviceName: String, deviceKind: String,
                           inviteToken: String? = nil,
                           onCode: @escaping @Sendable (TetherNearbyCode) async -> Void,
                           onHostApproved: @escaping @Sendable () async -> Void = {},
                           onStoring: @escaping @Sendable () async -> Void = {},
                           decision: @escaping @Sendable () async -> Bool?) async throws -> TetherNearbyOutcome
    {
        guard case .privateNetwork = route else { throw TetherClientError.nearbyRefused }
        guard !pairingBusy else { throw TetherClientError.operationInProgress }
        pairingBusy = true
        defer { pairingBusy = false }
        let identity = try await identities.identity(appID: appID)
        let session = try await ClientSession.connect(route: route, identity: identity, appID: appID,
                                                      pin: nil, allowLoopback: allowLoopback)
        do {
            // The flow applies the approval rules: an answer counts only after the code has been up
            // for a second and the decision has read undecided since it appeared; a decline wins.
            var request: [String: Any] = [
                "command": "nearby.begin", "app": appID, "binding": session.binding.base64EncodedString(),
                "clientKey": identity.publicKey.base64EncodedString(), "hostKey": session.peer.base64EncodedString(),
                "name": deviceName, "kind": deviceKind,
            ]
            if let inviteToken { request["inviteToken"] = inviteToken }
            let (flow, steps) = try TetherFlow.begin(request)
            let outcome = try await drive(flow, steps, session: session, route: route, identity: identity,
                                          onCode: onCode, onHostApproved: onHostApproved, onStoring: onStoring, decision: decision)
            await session.close()
            return outcome
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
