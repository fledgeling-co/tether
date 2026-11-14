import Foundation
import Observation

public struct TetherHostService: Codable, Equatable, Identifiable, Sendable {
    public let id: String
    public let kind: TetherServiceKind
    public init(id: String, kind: TetherServiceKind) {
        self.id = id; self.kind = kind
    }
}

public struct TetherHostStatus: Codable, Equatable, Sendable {
    public let services: [TetherHostService]
    public init(services: [TetherHostService]) {
        self.services = services
    }
}

public enum TetherNearbyResult: Equatable, Sendable {
    case paired(TetherManagedHost)
    case declined
    case expired
}

public enum TetherLocalForgetResult: Equatable, Sendable {
    case localTrustRemovedHostUnchanged
}

public enum TetherConnectionState: Equatable, Sendable {
    case offline, connecting, connected, reconnecting, revoked, identityMismatch, pending
}

public struct TetherManagedHost: Identifiable, Equatable, Sendable {
    public var id: String {
        record.hostKey.base64EncodedString()
    }

    public let record: TetherPeerRecord
    public internal(set) var displayName: String
    public internal(set) var state: TetherConnectionState
    public internal(set) var services: [TetherHostService]
    public internal(set) var lastChecked: Date?
}

public struct TetherReconnectPolicy: Sendable {
    public let retryDelays: [Duration]
    public let probeInterval: Duration
    public init(retryDelays: [Duration] = [.seconds(1), .seconds(2), .seconds(4)],
                probeInterval: Duration = .seconds(15)) throws
    {
        guard retryDelays.count <= 5,
              retryDelays.allSatisfy({ $0 >= .milliseconds(10) && $0 <= .seconds(30) }),
              probeInterval >= .milliseconds(10), probeInterval <= .seconds(300)
        else {
            throw TetherClientError.invalidProtocol
        }
        self.retryDelays = retryDelays; self.probeInterval = probeInterval
    }
}

/// Injectable for app adapters and deterministic tests; production uses TetherClient.
public protocol TetherClientManaging: Sendable {
    var appID: String { get }
    func records() async throws -> [TetherPeerRecord]
    func pair(route: TetherRoute, code: String) async throws -> TetherPeerRecord
    func recover(_ record: TetherPeerRecord) async throws -> TetherPeerRecord
    func status(_ record: TetherPeerRecord) async throws -> TetherHostStatus
    func updateRoute(_ record: TetherPeerRecord, to route: TetherRoute) async throws -> TetherPeerRecord
    func leave(_ record: TetherPeerRecord) async throws
    func forgetLocally(_ record: TetherPeerRecord) async throws -> TetherLocalForgetResult
    func discardPendingPairing(_ record: TetherPeerRecord) async throws
    func openService(_ name: String, kind: TetherServiceKind, peer: TetherPeerRecord) async throws -> TetherServiceStream
    func openMedia(_ name: String, peer: TetherPeerRecord) async throws -> TetherMediaSession
    func pairNearby(route: TetherRoute, deviceName: String, deviceKind: String, inviteToken: String?,
                    onCode: @escaping @Sendable (TetherNearbyCode) async -> Void,
                    onHostApproved: @escaping @Sendable () async -> Void,
                    onStoring: @escaping @Sendable () async -> Void,
                    decision: @escaping @Sendable () async -> Bool?) async throws -> TetherNearbyOutcome
}

public extension TetherClientManaging {
    func pairNearby(route _: TetherRoute, deviceName _: String, deviceKind _: String, inviteToken _: String?,
                    onCode _: @escaping @Sendable (TetherNearbyCode) async -> Void,
                    onHostApproved _: @escaping @Sendable () async -> Void,
                    onStoring _: @escaping @Sendable () async -> Void,
                    decision _: @escaping @Sendable () async -> Bool?) async throws -> TetherNearbyOutcome
    {
        throw TetherClientError.nearbyRefused
    }

    func openMedia(_: String, peer _: TetherPeerRecord) async throws -> TetherMediaSession {
        throw TetherClientError.mediaUnavailable
    }

    func updateRoute(_: TetherPeerRecord, to _: TetherRoute) async throws -> TetherPeerRecord {
        throw TetherClientError.invalidRoute
    }
}

extension TetherClient: TetherClientManaging {}

/// Swift weak loads retain the returned actor for the duration of each operation. The reference
/// is assigned only during initialization; ARC clears it atomically when its actor is released.
private final class WeakResource<T: AnyObject & Sendable>: @unchecked Sendable {
    weak var value: T?
    init(_ value: T) {
        self.value = value
    }
}

/// Each host has its own pinned record, monitor and streams. Selection never changes another
/// host's route or trust. Call stopMonitoring() when the app's owning scene stops observing.
@MainActor @Observable
public final class TetherConnectionStore {
    /// This manager admits six data streams per host, leaving room for controls within its own
    /// session budget. Other devices still share the host's total connection capacity.
    public nonisolated static let maximumStreamsPerHost = 6
    public let appID: String

    public private(set) var hosts: [TetherManagedHost] = []
    public var selectedHostID: String?
    @ObservationIgnored private let client: any TetherClientManaging
    @ObservationIgnored private let metadata: any TetherHostMetadataPersistence
    @ObservationIgnored private var streamGenerations: [String: UUID] = [:]
    @ObservationIgnored private let policy: TetherReconnectPolicy
    @ObservationIgnored private var monitors: [String: Task<Void, Never>] = [:]
    @ObservationIgnored private var generations: [String: UUID] = [:]
    @ObservationIgnored private var streams: [String: [UUID: WeakResource<TetherServiceStream>]] = [:]
    @ObservationIgnored private var media: [String: [UUID: WeakResource<TetherMediaSession>]] = [:]
    @ObservationIgnored private var streamReservations: [String: Int] = [:]
    @ObservationIgnored private var loadGeneration = UUID()
    @ObservationIgnored private var mutations = Set<String>()

    public init(client: any TetherClientManaging, reconnectPolicy: TetherReconnectPolicy? = nil,
                metadata: any TetherHostMetadataPersistence = TetherUserDefaultsHostMetadata()) throws
    {
        let scope = client.appID
        try Bridge.validateScope(scope)
        appID = scope
        self.client = client; self.metadata = metadata
        policy = try reconnectPolicy ?? TetherReconnectPolicy()
    }

    deinit {
        for task in monitors.values {
            task.cancel()
        }
        let active = streams.values.flatMap { $0.values.compactMap(\.value) }
        let datagrams = media.values.flatMap { $0.values.compactMap(\.value) }
        Task {
            for stream in active {
                await stream.close()
            }
            for session in datagrams {
                await session.close()
            }
        }
    }

    public func load() async throws {
        let token = UUID(); loadGeneration = token
        let records = try await client.records()
        guard loadGeneration == token else { throw TetherClientError.operationInProgress }
        guard records.allSatisfy({ $0.appID == appID && $0.hostKey.count == 32 && $0.clientKey.count == 32 }),
              Set(records.map { $0.hostKey }).count == records.count else { throw TetherError.invalidScope }
        let ids = Set(records.map { $0.hostKey.base64EncodedString() })
        for id in Set(monitors.keys).union(streams.keys).union(media.keys).subtracting(ids) {
            disconnect(hostID: id)
        }
        var names: [Data: String] = [:]
        for record in records {
            let storedName = await metadata.name(appID: appID, hostKey: record.hostKey)
            names[record.hostKey] = storedName.flatMap(validName) ?? defaultName(record)
            guard loadGeneration == token else { throw TetherClientError.operationInProgress }
        }
        hosts = records.map { record in
            let id = record.hostKey.base64EncodedString()
            let name = names[record.hostKey] ?? defaultName(record)
            if var existing = hosts.first(where: { $0.id == id }), existing.record == record {
                existing.displayName = name; return existing
            }
            disconnect(hostID: id)
            return TetherManagedHost(record: record, displayName: name,
                                     state: record.confirmed ? .offline : .pending,
                                     services: [], lastChecked: nil)
        }.sorted { $0.id < $1.id }
        if selectedHostID == nil || !ids.contains(selectedHostID ?? "") {
            selectedHostID = hosts.first?.id
        }
    }

    @discardableResult
    public func pair(route: TetherRoute, code: String) async throws -> TetherManagedHost {
        do {
            let record = try await client.pair(route: route, code: code)
            try Task.checkCancellation()
            try await load()
            try Task.checkCancellation()
            let id = record.hostKey.base64EncodedString()
            selectedHostID = id
            connect(hostID: id)
            return try host(id)
        } catch {
            // Pairing may have saved a durable pending record before its acknowledgement failed.
            // Reload that state so recovery remains visible; never discard trust on this path.
            try? await load()
            throw error
        }
    }

    public func connect(hostID: String) {
        guard let record = hosts.first(where: { $0.id == hostID })?.record, !mutations.contains(hostID) else { return }
        cancelMonitor(hostID)
        guard record.confirmed else { update(hostID, state: .pending); return }
        update(hostID, state: .connecting)
        let generation = UUID()
        generations[hostID] = generation
        let client = client; let policy = policy
        monitors[hostID] = Task { [weak self] in
            var failures = 0
            while !Task.isCancelled {
                do {
                    let status = try await client.status(record)
                    guard !Task.isCancelled, self?.generations[hostID] == generation else { return }
                    self?.update(hostID, state: .connected, status: status)
                    failures = 0
                    try await Task.sleep(for: policy.probeInterval)
                } catch {
                    guard !Task.isCancelled, self?.generations[hostID] == generation else { return }
                    if let error = error as? TetherClientError {
                        switch error {
                        case .identityMismatch: self?.unavailable(hostID, state: .identityMismatch); return
                        case .peerRevoked: self?.unavailable(hostID, state: .revoked); return
                        case .pairingPending: self?.update(hostID, state: .pending); return
                        default: break
                        }
                    }
                    guard failures < policy.retryDelays.count else { self?.unavailable(hostID, state: .offline); return }
                    self?.update(hostID, state: .reconnecting)
                    do { try await Task.sleep(for: policy.retryDelays[failures]) } catch { return }
                    failures += 1
                }
            }
        }
    }

    public func reconnect(hostID: String) {
        connect(hostID: hostID)
    }

    public func disconnect(hostID: String) {
        cancelMonitor(hostID)
        streamGenerations[hostID] = UUID()
        update(hostID, state: hosts.first(where: { $0.id == hostID })?.record.confirmed == false ? .pending : .offline)
        let owned = (streams.removeValue(forKey: hostID) ?? [:]).values.compactMap(\.value)
        let datagrams = (media.removeValue(forKey: hostID) ?? [:]).values.compactMap(\.value)
        Task {
            for stream in owned {
                await stream.close()
            }
            for session in datagrams {
                await session.close()
            }
        }
    }

    public func stopMonitoring() {
        for id in Set(monitors.keys).union(streams.keys).union(media.keys) {
            disconnect(hostID: id)
        }
    }

    public func recover(hostID: String) async throws {
        let record = try host(hostID).record
        try beginMutation(hostID)
        defer { mutations.remove(hostID) }
        _ = try await client.recover(record)
        try await load()
    }

    public func discardPendingPairing(hostID: String) async throws {
        let record = try host(hostID).record
        try beginMutation(hostID)
        defer { mutations.remove(hostID) }
        try await client.discardPendingPairing(record)
        try await load()
    }

    public func leave(hostID: String) async throws {
        let record = try host(hostID).record
        try beginMutation(hostID)
        defer { mutations.remove(hostID) }
        // Preserve trust on every failure; only the client deletes after a durable host ack.
        try await client.leave(record)
        disconnect(hostID: hostID)
        try await load()
    }

    /// Authenticate the candidate route against the existing pins before replacing it. Failure
    /// preserves this host's current route and streams; other hosts are never disconnected.
    public func changeRoute(hostID: String, to route: TetherRoute) async throws {
        let record = try host(hostID).record
        guard mutations.insert(hostID).inserted else { throw TetherClientError.operationInProgress }
        let resume = generations[hostID] != nil
        cancelMonitor(hostID)
        defer {
            mutations.remove(hostID)
            if resume {
                connect(hostID: hostID)
            }
        }
        let replacement = try await client.updateRoute(record, to: route)
        // Existing data streams survive a failed candidate probe. Only the successful CAS reaches here.
        disconnect(hostID: hostID)
        loadGeneration = UUID()
        if let index = hosts.firstIndex(where: { $0.id == hostID }) {
            hosts[index] = TetherManagedHost(record: replacement, displayName: hosts[index].displayName,
                                             state: .offline, services: [], lastChecked: nil)
        }
        // Publish the committed generation before another awaited refresh can supersede this one.
        // A resumed monitor can therefore never probe the old generation after our own CAS.
        try await load()
    }

    @discardableResult
    public func forgetLocally(hostID: String) async throws -> TetherLocalForgetResult {
        let record = try host(hostID).record
        try beginMutation(hostID)
        defer { mutations.remove(hostID) }
        let result = try await client.forgetLocally(record)
        disconnect(hostID: hostID)
        try await load()
        return result
    }

    public func openService(_ name: String, kind: TetherServiceKind, hostID: String) async throws -> TetherServiceStream {
        let record = try host(hostID).record
        guard !mutations.contains(hostID) else { throw TetherClientError.operationInProgress }
        let epoch = try await reserveSlot(hostID: hostID, record: record)
        defer { releaseReservation(hostID) }
        let stream = try await client.openService(name, kind: kind, peer: record)
        guard hosts.contains(where: { $0.record == record }), !mutations.contains(hostID),
              streamGenerations[hostID] == epoch
        else {
            await stream.close(); throw TetherClientError.identityMismatch
        }
        streams[hostID, default: [:]][UUID()] = WeakResource(stream)

        return stream
    }

    public func openReliablePacketStream(_ name: String, hostID: String) async throws -> TetherServiceStream {
        try await openService(name, kind: .udp, hostID: hostID)
    }

    public func openMedia(_ name: String, hostID: String) async throws -> TetherMediaSession {
        let record = try host(hostID).record
        guard !mutations.contains(hostID) else { throw TetherClientError.operationInProgress }
        let epoch = try await reserveSlot(hostID: hostID, record: record)
        defer { releaseReservation(hostID) }
        let session = try await client.openMedia(name, peer: record)
        guard hosts.contains(where: { $0.record == record }), !mutations.contains(hostID),
              streamGenerations[hostID] == epoch
        else {
            await session.close(); throw TetherClientError.identityMismatch
        }
        media[hostID, default: [:]][UUID()] = WeakResource(session)
        return session
    }

    private func reserveSlot(hostID: String, record: TetherPeerRecord) async throws -> UUID {
        let epoch = streamGenerations[hostID] ?? UUID(); streamGenerations[hostID] = epoch
        for (id, weak) in streams[hostID] ?? [:] {
            guard let stream = weak.value else { streams[hostID]?.removeValue(forKey: id); continue }
            if await stream.isClosed {
                streams[hostID]?.removeValue(forKey: id)
            }
        }
        for (id, weak) in media[hostID] ?? [:] {
            guard let session = weak.value else { media[hostID]?.removeValue(forKey: id); continue }
            if await session.isClosed {
                media[hostID]?.removeValue(forKey: id)
            }
        }
        guard hosts.contains(where: { $0.record == record }), !mutations.contains(hostID),
              streamGenerations[hostID] == epoch else { throw TetherClientError.identityMismatch }
        let active = (streams[hostID]?.count ?? 0) + (media[hostID]?.count ?? 0)
        guard active + (streamReservations[hostID] ?? 0) < Self.maximumStreamsPerHost else {
            throw TetherClientError.streamLimit
        }
        streamReservations[hostID, default: 0] += 1
        return epoch
    }

    private func releaseReservation(_ hostID: String) {
        let remaining = (streamReservations[hostID] ?? 1) - 1
        if remaining == 0 {
            streamReservations.removeValue(forKey: hostID)
        } else {
            streamReservations[hostID] = remaining
        }
    }

    /// Pairs with a nearby computer by comparing a code, then selects and connects it.
    public func pairNearby(route: TetherRoute, deviceName: String, deviceKind: String,
                           inviteToken: String? = nil,
                           onCode: @escaping @Sendable (TetherNearbyCode) async -> Void,
                           onHostApproved: @escaping @Sendable () async -> Void,
                           onStoring: @escaping @Sendable () async -> Void = {},
                           decision: @escaping @Sendable () async -> Bool?) async throws -> TetherNearbyResult
    {
        do {
            let outcome = try await client.pairNearby(route: route, deviceName: deviceName, deviceKind: deviceKind,
                                                      inviteToken: inviteToken,
                                                      onCode: onCode, onHostApproved: onHostApproved, onStoring: onStoring,
                                                      decision: decision)
            guard case let .paired(record) = outcome else { return outcome == .declined ? .declined : .expired }
            try await load()
            let id = record.hostKey.base64EncodedString()
            selectedHostID = id
            connect(hostID: id)
            return .paired(try host(id))
        } catch {
            try? await load()
            throw error
        }
    }

    public func renameHost(hostID: String, name: String) async throws {
        let record = try host(hostID).record
        guard let trimmed = validName(name) else { throw TetherClientError.invalidProtocol }
        await metadata.setName(trimmed, appID: appID, hostKey: record.hostKey)
        if let index = hosts.firstIndex(where: { $0.record == record }) {
            hosts[index].displayName = trimmed
        }
    }

    private func validName(_ name: String) -> String? {
        let value = name.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !value.isEmpty, value.count <= 80,
              !value.unicodeScalars.contains(where: { CharacterSet.controlCharacters.contains($0) }) else { return nil }
        return value
    }

    private func defaultName(_ record: TetherPeerRecord) -> String {
        switch record.route {
        case let .privateNetwork(host, port): return "\(host.contains(":") ? "[\(host)]" : host):\(port)"
        case let .cloud(_, hostID): return "Host " + hostID.prefix(8)
        }
    }

    private func host(_ id: String) throws -> TetherManagedHost {
        guard let host = hosts.first(where: { $0.id == id }), host.record.appID == appID else {
            throw TetherError.invalidScope
        }
        return host
    }

    private func beginMutation(_ id: String) throws {
        guard mutations.insert(id).inserted else { throw TetherClientError.operationInProgress }
        disconnect(hostID: id)
    }

    private func cancelMonitor(_ id: String) {
        generations.removeValue(forKey: id); monitors.removeValue(forKey: id)?.cancel()
    }

    private func unavailable(_ id: String, state: TetherConnectionState) {
        disconnect(hostID: id)
        update(id, state: state)
    }

    private func update(_ id: String, state: TetherConnectionState, status: TetherHostStatus? = nil) {
        guard let index = hosts.firstIndex(where: { $0.id == id }) else { return }
        hosts[index].state = state
        hosts[index].services = status?.services ?? []
        if status != nil {
            hosts[index].lastChecked = Date()
        }
    }
}
