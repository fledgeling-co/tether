import Foundation
import Testing
@testable import TetherKit

private actor MediaBackendFixture: MediaBackend {
    var connecting = false
    var polls = 0
    var connectingPolls = 0
    func slowStartup() {
        connectingPolls = 10
    }

    var backpressure = false
    var sent: [Data] = []
    var incoming: [Data] = []
    var receiveEntered = false
    private var holdReceive = false
    private var receiveContinuation: CheckedContinuation<MediaNativeReceive, Never>?
    func holdNextReceive() {
        holdReceive = true
    }

    func deliverHeld(_ packet: Data) {
        receiveContinuation?.resume(returning: .data(packet)); receiveContinuation = nil
    }

    var closes = 0
    var sendEntered = false
    var sendDelay: Duration = .zero
    func delaySends() {
        sendDelay = .seconds(10)
    }

    func remainConnecting() {
        connecting = true
    }

    func refuseSends() {
        backpressure = true
    }

    func enqueue(_ data: Data) {
        incoming.append(data)
    }

    func poll(_: UInt64) -> MediaNativeState {
        polls += 1
        return connecting || polls <= connectingPolls ? .connecting : .ready(1152)
    }

    func send(_ data: Data, handle _: UInt64) async throws -> Bool {
        sendEntered = true; defer { sendEntered = false }
        if sendDelay > .zero {
            try await Task.sleep(for: sendDelay)
        }
        if backpressure {
            return false
        }; sent.append(data); return true
    }

    func receive(_: UInt64) async -> MediaNativeReceive {
        if holdReceive {
            holdReceive = false; receiveEntered = true
            // Deliberately ignore cancellation until the test releases a native data result.
            return await withCheckedContinuation { receiveContinuation = $0 }
        }
        return incoming.isEmpty ? .pending : .data(incoming.removeFirst())
    }

    func statistics(_: UInt64) -> TetherMediaStatistics {
        TetherMediaStatistics(roundTripMilliseconds: 1.5, bytesSent: UInt64(sent.reduce(0) { $0 + $1.count }),
                              bytesReceived: 0, packetsSent: UInt64(sent.count), packetsReceived: 0, dropped: 0)
    }

    func close(_: UInt64) {
        closes += 1
    }
}

private actor MediaLeaseFixture: MediaLeaseControl {
    var failure = false
    var types: [String] = []
    var closes = 0
    func failHeartbeats() {
        failure = true
    }

    func sendControl(_ value: [String: String]) {
        types.append(value["type"] ?? "")
    }

    func control(expecting type: String) throws -> [String: String] {
        if failure, type == "media.alive" {
            throw TetherClientError.connectionClosed
        }
        return ["type": type]
    }

    func close() {
        closes += 1
    }
}

private actor MediaReleaseFixture {
    var count = 0
    func released() {
        count += 1
    }
}

private actor ManagedMediaMetadata: TetherHostMetadataPersistence {
    func name(appID _: String, hostKey _: Data) -> String? {
        nil
    }

    func setName(_: String, appID _: String, hostKey _: Data) {}
}

private actor ManagedMediaClient: TetherClientManaging {
    nonisolated let appID = "app.media.managed"
    let backend: MediaBackendFixture
    let control: MediaLeaseFixture
    let release: MediaReleaseFixture
    var values: [TetherPeerRecord]
    init(backend: MediaBackendFixture, control: MediaLeaseFixture, release: MediaReleaseFixture) {
        self.backend = backend; self.control = control; self.release = release
        values = [TetherPeerRecord(appID: appID, hostKey: Data(repeating: 1, count: 32), clientKey: Data(repeating: 2, count: 32),
                                   route: .privateNetwork(host: "127.0.0.1", port: 7445), confirmed: true)]
    }

    func records() -> [TetherPeerRecord] {
        values
    }

    func removeRecords() {
        values = []
    }

    func status(_: TetherPeerRecord) -> TetherHostStatus {
        TetherHostStatus(services: [])
    }

    func pair(route _: TetherRoute, code _: String) throws -> TetherPeerRecord {
        throw TetherClientError.serviceRefused
    }

    func recover(_: TetherPeerRecord) throws -> TetherPeerRecord {
        throw TetherClientError.serviceRefused
    }

    func discardPendingPairing(_: TetherPeerRecord) {}
    func leave(_: TetherPeerRecord) {
        values = []
    }

    func forgetLocally(_: TetherPeerRecord) -> TetherLocalForgetResult {
        values = []; return .localTrustRemovedHostUnchanged
    }

    func openService(_: String, kind _: TetherServiceKind, peer _: TetherPeerRecord) throws -> TetherServiceStream {
        throw TetherClientError.serviceRefused
    }

    func openMedia(_: String, peer _: TetherPeerRecord) async throws -> TetherMediaSession {
        let release = release
        return try await TetherMediaSession.ready(backend: backend, control: control, handle: 42, lease: "synthetic",
                                                  maximum: 1200, heartbeatInterval: .milliseconds(20)) { await release.released() }
    }
}

@Suite("Native media session lifetime and bounds")
struct MediaSessionTests {
    private func wait(_ condition: @Sendable () async -> Bool) async throws {
        let deadline = ContinuousClock.now.advanced(by: .seconds(2))
        while !(await condition()) {
            guard ContinuousClock.now < deadline else { throw TetherClientError.timeout }
            try await Task.sleep(for: .milliseconds(10))
        }
    }

    private func ready(_ backend: MediaBackendFixture, _ control: MediaLeaseFixture,
                       _ release: MediaReleaseFixture) async throws -> TetherMediaSession
    {
        try await TetherMediaSession.ready(backend: backend, control: control, handle: 42, lease: "synthetic",
                                           maximum: 1200, heartbeatInterval: .milliseconds(20)) { await release.released() }
    }

    @Test func cloudMediaRefusesWithoutFallbackOrTrustReset() async throws {
        let peers = TetherPeerStore(persistence: GenerationPeerFixture())
        let app = "app.media.tests"
        let pending = try TetherPeerRecord(appID: app, hostKey: Data(repeating: 1, count: 32),
                                           clientKey: Data(repeating: 2, count: 32),
                                           route: .cloud(relayURL: #require(URL(string: "wss://relay.example/tether")),
                                                         hostID: String(repeating: "a", count: 52)), confirmed: false)
        try await peers.begin(pending); let record = try await peers.confirm(pending)
        let client = try TetherClient(appID: app, peers: peers)
        do { _ = try await client.openMedia("media", peer: record); Issue.record("cloud media silently changed transport") }
        catch TetherClientError.mediaUnavailable {}
        #expect(try await client.records() == [record])
    }

    @Test func leaseHeartbeatsRunWhileNativeConnectIsPending() async throws {
        let backend = MediaBackendFixture(), control = MediaLeaseFixture(), release = MediaReleaseFixture()
        await backend.slowStartup()
        let session = try await ready(backend, control, release)
        #expect(await control.types.contains("media.heartbeat"))
        await session.close()
    }

    @MainActor @Test func managedDropAndRemovedHostReleaseResources() async throws {
        let backend = MediaBackendFixture(), control = MediaLeaseFixture(), release = MediaReleaseFixture()
        let client = ManagedMediaClient(backend: backend, control: control, release: release)
        let store = try TetherConnectionStore(client: client, metadata: ManagedMediaMetadata())
        try await store.load(); let id = try #require(store.hosts.first?.id)
        var session: TetherMediaSession? = try await store.openMedia("media", hostID: id)
        #expect(session != nil); session = nil
        try await wait { await release.count == 1 }
        #expect(store.hosts.count == 1)
        let second = try await store.openMedia("media", hostID: id)
        await client.removeRecords()
        try await store.load()
        try await wait { await second.state == .closed }
        #expect(store.hosts.isEmpty)
        #expect(await release.count == 2)
    }

    @Test func negotiatedBoundPreservesPacketsAndCloseIsIdempotent() async throws {
        let backend = MediaBackendFixture(), control = MediaLeaseFixture(), release = MediaReleaseFixture()
        let session = try await ready(backend, control, release)
        #expect(session.maximumDatagramSize == 1152)
        do { try await session.send(Data(repeating: 1, count: 1153)); Issue.record("oversized datagram accepted") }
        catch TetherClientError.invalidFrame {}
        try await session.send(Data())
        await backend.enqueue(Data())
        #expect(try await session.receive() == Data())
        #expect(try await session.statistics().packetsSent == 1)
        await session.close(); await session.close()
        #expect(await backend.closes == 1)
        #expect(await control.closes == 1)
        #expect(await release.count == 1)
    }

    @Test func failedLeaseHeartbeatClosesNativeTransportAndReleasesSlot() async throws {
        let backend = MediaBackendFixture(), control = MediaLeaseFixture(), release = MediaReleaseFixture()
        await control.failHeartbeats()
        let session = try await ready(backend, control, release)
        try await wait { await session.state == .failed }
        #expect(await backend.closes == 1)
        #expect(await release.count == 1)
        #expect(await control.closes == 1)
    }

    @Test func cancellingPendingConnectClosesHandleAndOriginatingLease() async throws {
        let backend = MediaBackendFixture(), control = MediaLeaseFixture(), release = MediaReleaseFixture()
        await backend.remainConnecting()
        let task = Task { try await ready(backend, control, release) }
        try await Task.sleep(for: .milliseconds(20)); task.cancel()
        do { _ = try await task.value; Issue.record("cancelled connect completed") } catch is CancellationError {}
        #expect(await backend.closes == 1)
        #expect(await control.closes == 1)
        #expect(await release.count == 1)
    }

    @Test func cancelledNativeDataResultCannotEscapeOrLeakItsLease() async throws {
        let backend = MediaBackendFixture(), control = MediaLeaseFixture(), release = MediaReleaseFixture()
        await backend.holdNextReceive()
        let session = try await ready(backend, control, release)
        let receive = Task { try await session.receive() }
        try await wait { await backend.receiveEntered }
        receive.cancel()
        await backend.deliverHeld(Data([0x5A]))
        do { _ = try await receive.value; Issue.record("canceled native data escaped and retained the lease") }
        catch is CancellationError {}
        #expect(await session.state == .failed)
        #expect(await backend.closes == 1)
        #expect(await control.closes == 1)
        #expect(await release.count == 1)
    }

    @Test func pendingReceiveCancellationClosesItsLease() async throws {
        let backend = MediaBackendFixture(), control = MediaLeaseFixture(), release = MediaReleaseFixture()
        let session = try await ready(backend, control, release)
        let receiving = Task { try await session.receive() }
        try await Task.sleep(for: .milliseconds(20)); receiving.cancel()
        do { _ = try await receiving.value; Issue.record("cancelled receive completed") } catch is CancellationError {}
        #expect(await session.state == .failed)
        #expect(await backend.closes == 1)
        #expect(await release.count == 1)
    }

    @Test func oneProducerAndCancellationBoundPendingNativeWork() async throws {
        let backend = MediaBackendFixture(), control = MediaLeaseFixture(), release = MediaReleaseFixture()
        await backend.delaySends()
        let session = try await ready(backend, control, release)
        let sending = Task { try await session.send(Data([1])) }
        try await wait { await backend.sendEntered }
        do { try await session.send(Data([2])); Issue.record("concurrent producer admitted") }
        catch TetherClientError.operationInProgress {}
        sending.cancel()
        do { try await sending.value; Issue.record("cancelled producer completed") } catch is CancellationError {}
        #expect(await backend.closes == 1)
        #expect(await release.count == 1)
    }

    @Test func backpressureIsAnExplicitRefusalWithoutAutomaticRetry() async throws {
        let backend = MediaBackendFixture(), control = MediaLeaseFixture(), release = MediaReleaseFixture()
        await backend.refuseSends()
        let session = try await ready(backend, control, release)
        do { try await session.send(Data([1])); Issue.record("backpressure was ignored") }
        catch TetherClientError.mediaBackpressure {}
        #expect(await session.state == .ready)
        #expect(await backend.sent.isEmpty)
        await session.close()
    }

    @Test func droppingSessionClosesNativeHandleAndNoiseLease() async throws {
        let backend = MediaBackendFixture(), control = MediaLeaseFixture(), release = MediaReleaseFixture()
        var session: TetherMediaSession? = try await ready(backend, control, release)
        #expect(session != nil); session = nil
        try await wait { await release.count == 1 }
        #expect(await backend.closes == 1)
        #expect(await control.closes == 1)
    }
}
