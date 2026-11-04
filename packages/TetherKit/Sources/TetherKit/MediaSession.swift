import Foundation

protocol MediaLeaseControl: Sendable {
    func sendControl(_ value: [String: String]) async throws
    func control(expecting type: String) async throws -> [String: String]
    func close() async
}

private actor MediaLeasePump {
    private let control: any MediaLeaseControl
    private let lease: String
    private var heartbeat: Task<Void, Never>?
    private var stopping: Task<Void, Never>?
    private var failure: (@Sendable () async -> Void)?
    private(set) var failed = false
    init(control: any MediaLeaseControl, lease: String) {
        self.control = control; self.lease = lease
    }

    func start(interval: Duration) {
        let control = control, lease = lease
        heartbeat = Task { [weak self] in
            while !Task.isCancelled {
                do {
                    try await Task.sleep(for: interval)
                    try await withTetherDeadline(seconds: 3) {
                        try await control.sendControl(["type": "media.heartbeat", "lease_id": lease])
                        _ = try await control.control(expecting: "media.alive")
                    }
                } catch {
                    if !Task.isCancelled {
                        await self?.didFail()
                    }
                    return
                }
            }
        }
    }

    func onFailure(_ handler: @escaping @Sendable () async -> Void) {
        failure = handler
        if failed {
            Task { await handler() }
        }
    }

    private func didFail() {
        failed = true
        if let failure {
            Task { await failure() }
        }
    }

    func stop() async {
        if let stopping {
            await stopping.value; return
        }
        let heartbeat = heartbeat, control = control
        self.heartbeat = nil; failure = nil
        // Closing the originating Noise channel releases the host lease. Await its canceled
        // heartbeat instead of racing another control send against an in-flight heartbeat.
        let stopping = Task<Void, Never> {
            heartbeat?.cancel(); await control.close()
            if let heartbeat {
                await heartbeat.value
            }
        }
        self.stopping = stopping
        await stopping.value
    }
}

public enum TetherMediaState: Equatable, Sendable { case ready, closed, failed }

/// Authenticated native QUIC datagrams on the explicitly saved private/VPN route. Packets are
/// bounded by the actual negotiated maximum; the SDK never fragments or changes route on failure.
/// Canceling connect, send or receive closes the media session and its originating lease.
public actor TetherMediaSession {
    public nonisolated let maximumDatagramSize: Int
    public private(set) var state: TetherMediaState = .ready
    private let backend: any MediaBackend
    private let pump: MediaLeasePump
    private let handle: UInt64
    private let released: @Sendable () async -> Void
    private var sending = false
    private var receiving = false
    private var closed = false

    private init(backend: any MediaBackend, pump: MediaLeasePump, handle: UInt64,
                 maximum: Int, released: @escaping @Sendable () async -> Void)
    {
        self.backend = backend; self.pump = pump; self.handle = handle
        maximumDatagramSize = maximum; self.released = released
    }

    static func open(address: String, offer: MediaOffer, control: any MediaLeaseControl,
                     released: @escaping @Sendable () async -> Void) async throws -> TetherMediaSession
    {
        try offer.validate()
        try Task.checkCancellation()
        let backend = RustMediaBackend()
        let handle: UInt64
        do { handle = try await backend.start(address: address, offer: offer) }
        catch { await control.close(); await released(); throw error }
        return try await ready(backend: backend, control: control, handle: handle,
                               lease: offer.lease_id.base64EncodedString(), maximum: offer.max_datagram, released: released)
    }

    static func ready(backend: any MediaBackend, control: any MediaLeaseControl, handle: UInt64,
                      lease: String, maximum: Int, startupTimeout: Double = 15,
                      heartbeatInterval: Duration = .seconds(2),
                      released: @escaping @Sendable () async -> Void) async throws -> TetherMediaSession
    {
        let pump = MediaLeasePump(control: control, lease: lease)
        // The lease starts at media.ready, before QUIC is connected. Keep it alive throughout
        // native connection setup, whose single bounded attempt may exceed the five-second TTL.
        await pump.start(interval: heartbeatInterval)
        let negotiated: Int
        do {
            guard (1 ... 1200).contains(maximum) else { throw TetherClientError.invalidProtocol }
            negotiated = try await withTetherDeadline(seconds: startupTimeout) {
                while true {
                    try Task.checkCancellation()
                    guard !(await pump.failed) else { throw TetherClientError.connectionClosed }
                    switch try await backend.poll(handle) {
                    case .connecting: try await Task.sleep(for: .milliseconds(10))
                    case let .ready(size):
                        guard (1 ... 1200).contains(size) else { throw TetherClientError.invalidProtocol }
                        return min(maximum, size)
                    case .failed, .closed: throw TetherClientError.connectionClosed
                    }
                }
            }
            try Task.checkCancellation()
        } catch { await backend.close(handle); await pump.stop(); await released(); throw error }
        let session = TetherMediaSession(backend: backend, pump: pump, handle: handle,
                                         maximum: negotiated, released: released)
        await pump.onFailure { [weak session] in await session?.terminate(.failed) }
        guard !(await pump.failed) else {
            await session.terminate(.failed); throw TetherClientError.connectionClosed
        }
        return session
    }

    deinit {
        let backend = backend, pump = pump, handle = handle, released = released
        let needsClose = !closed
        Task {
            if needsClose {
                await backend.close(handle); await pump.stop(); await released()
            }
        }
    }

    public var isClosed: Bool {
        closed
    }

    public func send(_ packet: Data) async throws {
        guard !closed else { throw TetherError.closed }
        guard packet.count <= maximumDatagramSize else { throw TetherClientError.invalidFrame }
        guard !sending else { throw TetherClientError.operationInProgress }
        sending = true; defer { sending = false }
        do {
            try Task.checkCancellation()
            let accepted = try await backend.send(packet, handle: handle)
            try Task.checkCancellation()
            guard !closed else { throw TetherError.closed }
            guard accepted else { throw TetherClientError.mediaBackpressure }
        } catch TetherClientError.mediaBackpressure { throw TetherClientError.mediaBackpressure }
        catch { await terminate(.failed); throw error }
    }

    /// One datagram per receive, including an empty datagram. No EOF sentinel or reassembly.
    public func receive() async throws -> Data {
        guard !closed else { throw TetherError.closed }
        guard !receiving else { throw TetherClientError.operationInProgress }
        receiving = true; defer { receiving = false }
        let deadline = ContinuousClock.now.advanced(by: .seconds(60))
        do {
            while true {
                try Task.checkCancellation()
                guard ContinuousClock.now < deadline else { throw TetherClientError.timeout }
                // Native receive_wait is bounded to 100 ms. A monotonic loop deadline avoids
                // an extra racing timer task, and cancellation closes/wakes the native wait.
                let result = try await backend.receive(handle)
                try Task.checkCancellation()
                guard !(await pump.failed) else { throw TetherClientError.connectionClosed }
                try Task.checkCancellation()
                guard !closed else { throw TetherError.closed }
                guard ContinuousClock.now < deadline else { throw TetherClientError.timeout }
                switch result {
                case .pending: await Task.yield()
                case let .data(bytes):
                    guard bytes.count <= maximumDatagramSize else { throw TetherClientError.invalidFrame }
                    return bytes
                case .closed, .failed: throw TetherClientError.connectionClosed
                }
            }
        } catch {
            await terminate(.failed)
            if Task.isCancelled {
                throw CancellationError()
            }
            throw error
        }
    }

    public func statistics() async throws -> TetherMediaStatistics {
        guard !closed else { throw TetherError.closed }
        return try await backend.statistics(handle)
    }

    public func close() async {
        await terminate(.closed)
    }

    private func terminate(_ finalState: TetherMediaState) async {
        guard !closed else { return }
        closed = true; state = finalState
        await backend.close(handle)
        await pump.stop()
        await released()
    }
}
