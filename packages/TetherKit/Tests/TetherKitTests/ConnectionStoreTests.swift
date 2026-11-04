import Foundation
import Testing
@testable import TetherKit

private actor MetadataFixture: TetherHostMetadataPersistence {
    var names: [String: String] = [:]
    var blocked = false
    private var blockKey: Data?
    private var continuation: CheckedContinuation<Void, Never>?
    func blockNext(_ key: Data) {
        blockKey = key
    }

    func release() {
        continuation?.resume(); continuation = nil; blocked = false
    }

    func name(appID: String, hostKey: Data) async -> String? {
        if blockKey == hostKey {
            blockKey = nil; blocked = true
            await withCheckedContinuation { continuation = $0 }
        }
        return names[appID + hostKey.base64EncodedString()]
    }

    func setName(_ name: String, appID: String, hostKey: Data) {
        names[appID + hostKey.base64EncodedString()] = name
    }
}

private actor ManagedClientFixture: TetherClientManaging {
    nonisolated let appID: String
    var values: [TetherPeerRecord]
    var errors: [Data: TetherClientError] = [:]
    var probes: [Data: Int] = [:]
    var delay: Duration = .zero
    var leaveError: TetherClientError?
    var pendingOnFailure = false
    var routeFailure: TetherClientError?
    func pairFailureLeavesPending() {
        pendingOnFailure = true
    }

    func failRoute() {
        routeFailure = .identityMismatch
    }

    func fast() {
        delay = .zero
    }

    init(_ records: [TetherPeerRecord], appID: String = "app.connection.tests") {
        values = records; self.appID = appID
    }

    func fail(_ key: Data, with error: TetherClientError) {
        errors[key] = error
    }

    func slow() {
        delay = .seconds(10)
    }

    func failLeave() {
        leaveError = .connectionClosed
    }

    func records() -> [TetherPeerRecord] {
        values
    }

    func count(_ key: Data) -> Int {
        probes[key, default: 0]
    }

    func pair(route: TetherRoute, code _: String) throws -> TetherPeerRecord {
        if pendingOnFailure {
            values.append(TetherPeerRecord(appID: appID, hostKey: Data(repeating: 7, count: 32),
                                           clientKey: Data(repeating: 9, count: 32), route: route, confirmed: false))
            throw TetherClientError.connectionClosed
        }
        throw TetherClientError.serviceRefused
    }

    func updateRoute(_ record: TetherPeerRecord, to route: TetherRoute) throws -> TetherPeerRecord {
        if let routeFailure {
            throw routeFailure
        }
        guard let index = values.firstIndex(of: record) else { throw TetherClientError.identityMismatch }
        let next = TetherPeerRecord(appID: appID, hostKey: record.hostKey, clientKey: record.clientKey, route: route, confirmed: true)
        values[index] = next; return next
    }

    func recover(_: TetherPeerRecord) throws -> TetherPeerRecord {
        throw TetherClientError.serviceRefused
    }

    func status(_ record: TetherPeerRecord) async throws -> TetherHostStatus {
        probes[record.hostKey, default: 0] += 1
        if delay > .zero {
            try? await Task.sleep(for: delay)
        }
        if let error = errors[record.hostKey] {
            throw error
        }
        guard values.contains(record) else { throw TetherClientError.identityMismatch }
        return TetherHostStatus(services: [TetherHostService(id: "api", kind: .tcp)])
    }

    func leave(_ record: TetherPeerRecord) throws {
        if let leaveError {
            throw leaveError
        }; values.removeAll { $0 == record }
    }

    func forgetLocally(_ record: TetherPeerRecord) -> TetherLocalForgetResult {
        values.removeAll { $0 == record }; return .localTrustRemovedHostUnchanged
    }

    func discardPendingPairing(_ record: TetherPeerRecord) {
        values.removeAll { $0 == record && !$0.confirmed }
    }

    func openService(_: String, kind _: TetherServiceKind, peer _: TetherPeerRecord) throws -> TetherServiceStream {
        throw TetherClientError.serviceRefused
    }
}

actor GenerationPeerFixture: TetherPeerPersistence {
    var values: [String: Data] = [:]
    var deleteBeforeReplace = false
    func raceDeletion() {
        deleteBeforeReplace = true
    }

    func key(_ app: String, _ host: Data) -> String {
        app + "|" + host.base64EncodedString()
    }

    func list(appID: String) -> [Data] {
        values.filter { $0.key.hasPrefix(appID + "|") }.map(\.value)
    }

    func load(appID: String, hostKey: Data) -> Data? {
        values[key(appID, hostKey)]
    }

    func save(_ value: Data, appID: String, hostKey: Data, createOnly: Bool) throws {
        let id = key(appID, hostKey)
        if createOnly, values[id] != nil {
            throw TetherClientError.pairingExists
        }
        values[id] = value
    }

    func discardPending(appID: String, hostKey: Data, pairingID: UUID) throws {
        try remove(appID: appID, hostKey: hostKey, pairingID: pairingID, confirmed: false)
    }

    func replaceConfirmed(_ value: Data, appID: String, hostKey: Data, expectedPairingID: UUID) throws {
        let id = key(appID, hostKey)
        if deleteBeforeReplace {
            values.removeValue(forKey: id); deleteBeforeReplace = false
        }
        guard let current = values[id],
              let record = try? JSONDecoder().decode(TetherPeerRecord.self, from: current),
              record.confirmed, record.pairingID == expectedPairingID else { throw TetherClientError.identityMismatch }
        values[id] = value
    }

    func removeConfirmed(appID: String, hostKey: Data, pairingID: UUID) throws {
        try remove(appID: appID, hostKey: hostKey, pairingID: pairingID, confirmed: true)
    }

    private func remove(appID: String, hostKey: Data, pairingID: UUID, confirmed: Bool) throws {
        let id = key(appID, hostKey)
        guard let data = values[id], let record = try? JSONDecoder().decode(TetherPeerRecord.self, from: data),
              record.pairingID == pairingID, record.confirmed == confirmed else { throw TetherClientError.identityMismatch }
        values.removeValue(forKey: id)
    }
}

@MainActor @Suite("Independent host connection management")
struct ConnectionStoreTests {
    private func record(_ byte: UInt8, confirmed: Bool = true, appID: String = "app.connection.tests") -> TetherPeerRecord {
        TetherPeerRecord(appID: appID, hostKey: Data(repeating: byte, count: 32),
                         clientKey: Data(repeating: 9, count: 32), route: .privateNetwork(host: "127.0.0.1", port: 7445),
                         confirmed: confirmed)
    }

    private func wait(_ condition: () -> Bool) async throws {
        let deadline = ContinuousClock.now.advanced(by: .seconds(2))
        while !condition() {
            guard ContinuousClock.now < deadline else { throw TetherClientError.timeout }
            try await Task.sleep(for: .milliseconds(10))
        }
    }

    @Test func savedHostsAreOfflineUntilTheirOwnAuthenticatedProbe() async throws {
        let a = record(1), b = record(2), pending = record(3, confirmed: false)
        let client = ManagedClientFixture([a, b, pending])
        let store = try TetherConnectionStore(client: client, metadata: MetadataFixture())
        try await store.load()
        #expect(store.hosts.filter { $0.state == .offline }.count == 2)
        #expect(store.hosts.first { !$0.record.confirmed }?.state == .pending)
        let aid = a.hostKey.base64EncodedString(), bid = b.hostKey.base64EncodedString()
        await client.fail(a.hostKey, with: .peerRevoked)
        store.connect(hostID: aid); store.connect(hostID: bid)
        try await wait { store.hosts.contains { $0.id == aid && $0.state == .revoked }
            && store.hosts.contains { $0.id == bid && $0.state == .connected }
        }
        store.disconnect(hostID: aid)
        #expect(store.hosts.first { $0.id == bid }?.state == .connected)
        #expect(store.hosts.first { $0.id == bid }?.services.map(\.id) == ["api"])
        #expect(await client.records().count == 3)
        store.stopMonitoring()
    }

    @Test func retriesAreBoundedAndCancellationCannotReviveAHost() async throws {
        let a = record(1); let client = ManagedClientFixture([a]); let id = a.hostKey.base64EncodedString()
        let policy = try TetherReconnectPolicy(retryDelays: [.milliseconds(10), .milliseconds(10)], probeInterval: .seconds(15))
        let store = try TetherConnectionStore(client: client, reconnectPolicy: policy, metadata: MetadataFixture())
        try await store.load(); await client.fail(a.hostKey, with: .connectionClosed)
        store.connect(hostID: id)
        try await wait { store.hosts.first?.state == .offline }
        #expect(await client.count(a.hostKey) == 3)
        await client.slow(); store.reconnect(hostID: id)
        try await Task.sleep(for: .milliseconds(20)); store.disconnect(hostID: id)
        try await Task.sleep(for: .milliseconds(20))
        #expect(store.hosts.first?.state == .offline)
    }

    @Test func identityFailureDoesNotResetTrustAndOfflineLeavePreservesIt() async throws {
        let a = record(1); let client = ManagedClientFixture([a]); let id = a.hostKey.base64EncodedString()
        let store = try TetherConnectionStore(client: client, metadata: MetadataFixture())
        try await store.load(); await client.fail(a.hostKey, with: .identityMismatch)
        store.connect(hostID: id); try await wait { store.hosts.first?.state == .identityMismatch }
        await client.failLeave()
        do { try await store.leave(hostID: id); Issue.record("offline leave removed trust") }
        catch TetherClientError.connectionClosed {}
        #expect(await client.records() == [a])
        #expect(store.hosts.count == 1)
        let result = try await store.forgetLocally(hostID: id)
        if case .localTrustRemovedHostUnchanged = result {} else {
            Issue.record("missing local-only result")
        }
        #expect(store.hosts.isEmpty)
    }

    @Test func nicknamesAreScopedAndDoNotChangePins() async throws {
        let a = record(1); let metadata = MetadataFixture(); let client = ManagedClientFixture([a])
        let store = try TetherConnectionStore(client: client, metadata: metadata)
        try await store.load(); let id = a.hostKey.base64EncodedString()
        try await store.renameHost(hostID: id, name: " Studio Mac ")
        #expect(store.hosts.first?.displayName == "Studio Mac")
        #expect(store.hosts.first?.record == a)
        #expect(await metadata.name(appID: "app.other", hostKey: a.hostKey) == nil)
        try await store.load(); #expect(store.hosts.first?.displayName == "Studio Mac")
    }

    @Test func foreignAppRecordsAreRefused() async throws {
        let client = ManagedClientFixture([record(1, appID: "app.foreign")])
        let store = try TetherConnectionStore(client: client, metadata: MetadataFixture())
        do { try await store.load(); Issue.record("foreign app loaded") } catch TetherError.invalidScope {}
        #expect(store.hosts.isEmpty)
    }

    @Test(arguments: [false, true])
    func lateMetadataLoadCannotRestoreOnlineStateOrRemovedTrust(removeHost: Bool) async throws {
        let a = record(1), b = record(2), metadata = MetadataFixture(), client = ManagedClientFixture([a, b])
        let store = try TetherConnectionStore(client: client, metadata: metadata)
        try await store.load()
        let id = a.hostKey.base64EncodedString()
        store.connect(hostID: id)
        try await wait { store.hosts.first(where: { $0.id == id })?.state == .connected }
        await metadata.blockNext(b.hostKey)
        let loading = Task { try await store.load() }
        defer { loading.cancel(); Task { await metadata.release() } }
        let deadline = ContinuousClock.now.advanced(by: .seconds(2))
        while !(await metadata.blocked) {
            guard ContinuousClock.now < deadline else { throw TetherClientError.timeout }
            try await Task.sleep(for: .milliseconds(10))
        }
        if removeHost {
            _ = await client.forgetLocally(a)
            try await store.load()
        } else {
            store.disconnect(hostID: id)
        }
        await metadata.release()
        do {
            try await loading.value; if removeHost {
                Issue.record("superseded refresh silently succeeded")
            }
        } catch TetherClientError.operationInProgress { #expect(removeHost) }
        if removeHost {
            #expect(!store.hosts.contains { $0.id == id })
        } else {
            #expect(store.hosts.first(where: { $0.id == id })?.state == .offline)
        }
        store.stopMonitoring()
    }

    @Test func routeCompareAndSwapCannotRestoreDeletedOrChangedTrust() async throws {
        let persistence = GenerationPeerFixture(); let peers = TetherPeerStore(persistence: persistence)
        let pending = record(1, confirmed: false)
        try await peers.begin(pending); let original = try await peers.confirm(pending)
        let nextRoute = TetherRoute.privateNetwork(host: "192.0.2.4", port: 7445)
        let changed = try await peers.replaceRoute(original, route: nextRoute)
        #expect(changed.pairingID != original.pairingID && changed.hostKey == original.hostKey)
        #expect(changed.clientKey == original.clientKey && changed.route == nextRoute)
        let client = try TetherClient(appID: original.appID, peers: peers)
        do { _ = try await client.openService("api", kind: .tcp, peer: original)
            Issue.record("stale generation silently opened the replacement route")
        } catch TetherClientError.identityMismatch {}
        do { _ = try await peers.replaceRoute(original, route: original.route); Issue.record("stale route replaced current trust") }
        catch TetherClientError.identityMismatch {}
        await persistence.raceDeletion()
        do { _ = try await peers.replaceRoute(changed, route: original.route); Issue.record("route update restored deleted trust") }
        catch TetherClientError.identityMismatch {}
        #expect(try await peers.records(appID: original.appID).isEmpty)
    }

    @Test func pendingPairFailureReloadsVisibleRecoveryState() async throws {
        let client = ManagedClientFixture([]); await client.pairFailureLeavesPending()
        let store = try TetherConnectionStore(client: client, metadata: MetadataFixture())
        do { _ = try await store.pair(route: .privateNetwork(host: "127.0.0.1", port: 7445), code: "ABCDEFGH")
            Issue.record("failed pair completed")
        } catch TetherClientError.connectionClosed {}
        #expect(store.hosts.count == 1 && store.hosts.first?.state == .pending)
    }

    @Test func routeProbeSuspendsOldMonitorAndResumesCorrectGeneration() async throws {
        let original = record(1), client = ManagedClientFixture([record(1)])
        let store = try TetherConnectionStore(client: client, metadata: MetadataFixture())
        try await store.load(); let id = original.hostKey.base64EncodedString()
        store.connect(hostID: id); try await wait { store.hosts.first?.state == .connected }
        await client.slow(); store.reconnect(hostID: id)
        let deadline = ContinuousClock.now.advanced(by: .seconds(2))
        while await client.count(original.hostKey) < 2 {
            guard ContinuousClock.now < deadline else { throw TetherClientError.timeout }
            try await Task.sleep(for: .milliseconds(10))
        }
        await client.fast()
        let route = TetherRoute.privateNetwork(host: "192.0.2.4", port: 7445)
        try await store.changeRoute(hostID: id, to: route)
        try await wait { store.hosts.first?.state == .connected }
        #expect(store.hosts.first?.record.route == route)
        await client.failRoute()
        do { try await store.changeRoute(hostID: id, to: original.route); Issue.record("substituted candidate accepted") }
        catch TetherClientError.identityMismatch {}
        try await wait { store.hosts.first?.state == .connected }
        #expect(store.hosts.first?.record.route == route)
        store.stopMonitoring()
    }

    @Test func invalidCustomClientScopeIsRefusedAtConstruction() {
        let client = ManagedClientFixture([], appID: "invalid|scope")
        do { _ = try TetherConnectionStore(client: client, metadata: MetadataFixture()); Issue.record("invalid app scope accepted") }
        catch TetherError.invalidScope {} catch { Issue.record(error) }
    }

    @Test func confirmedDeletionChecksAppAndGeneration() async throws {
        let persistence = GenerationPeerFixture(); let peers = TetherPeerStore(persistence: persistence)
        let first = record(1, confirmed: false)
        try await peers.begin(first); let confirmed = try await peers.confirm(first)
        let client = try TetherClient(appID: first.appID, peers: peers)
        let other = try TetherClient(appID: "app.other", peers: peers)
        do { _ = try await other.forgetLocally(confirmed); Issue.record("foreign app forgot trust") }
        catch TetherError.invalidScope {}
        try await peers.removeConfirmed(confirmed)
        let next = record(1, confirmed: false)
        try await peers.begin(next); let replacement = try await peers.confirm(next)
        do { _ = try await client.forgetLocally(confirmed); Issue.record("stale generation removed replacement") }
        catch TetherClientError.identityMismatch {}
        #expect(try await peers.records(appID: first.appID) == [replacement])
        _ = try await client.forgetLocally(replacement)
        #expect(try await peers.records(appID: first.appID).isEmpty)
    }
}
