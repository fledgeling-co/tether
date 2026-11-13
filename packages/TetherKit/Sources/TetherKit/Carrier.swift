import Foundation
@preconcurrency import Network

public enum TetherClientError: Error, Sendable {
    case invalidRoute, timeout, connectionClosed, invalidFrame, invalidProtocol
    case hostCapacity, mediaUnavailable, mediaBackpressure, peerRevoked, identityMismatch, pairingExists, pairingPending, serviceRefused, operationInProgress, streamLimit
    /// Nearby pairing: the host isn't accepting nearby requests, or only over the local network.
    case nearbyRefused
    /// Nearby pairing: this device was declined repeatedly and is paused for a while.
    case nearbyPaused
    /// Nearby pairing: the host is already showing other requests.
    case nearbyBusy
}

/// No automatic fallback. Changing between private and cloud routes is always a caller decision.
public enum TetherRoute: Codable, Equatable, Sendable {
    case privateNetwork(host: String, port: UInt16)
    case cloud(relayURL: URL, hostID: String)
}

protocol TetherCarrier: Sendable {
    func send(_ bytes: Data) async throws
    func receive() async throws -> Data
    func close() async
}

func withTetherDeadline<T: Sendable>(seconds: Double = 15,
                                     operation: @escaping @Sendable () async throws -> T) async throws -> T
{
    try await withThrowingTaskGroup(of: T.self) { group in
        group.addTask { try await operation() }
        group.addTask {
            try await Task.sleep(for: .seconds(seconds))
            throw TetherClientError.timeout
        }
        defer { group.cancelAll() }
        guard let result = try await group.next() else { throw TetherClientError.connectionClosed }
        return result
    }
}

private final class ReadyOnce: @unchecked Sendable {
    private let lock = NSLock()
    private var continuation: CheckedContinuation<Void, Error>?
    init(_ continuation: CheckedContinuation<Void, Error>) {
        self.continuation = continuation
    }

    func finish(_ result: Result<Void, Error>) {
        let pending = lock.withLock { let value = continuation; continuation = nil; return value }
        pending?.resume(with: result)
    }
}

actor DirectCarrier: TetherCarrier {
    private let connection: NWConnection
    private init(_ connection: NWConnection) {
        self.connection = connection
    }

    static func connect(host: String, port: UInt16) async throws -> DirectCarrier {
        guard !host.isEmpty, host.utf8.count <= 320, !host.contains("://"),
              !host.contains(where: { $0.isWhitespace }), port != 0,
              let endpointPort = NWEndpoint.Port(rawValue: port) else { throw TetherClientError.invalidRoute }
        let connection = NWConnection(host: NWEndpoint.Host(host), port: endpointPort, using: .tcp)
        do {
            try await withTetherDeadline {
                try await withTaskCancellationHandler {
                    try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
                        let once = ReadyOnce(continuation)
                        connection.stateUpdateHandler = { state in
                            switch state {
                            case .ready: once.finish(.success(())); connection.stateUpdateHandler = nil
                            case .failed, .cancelled:
                                once.finish(.failure(TetherClientError.connectionClosed))
                                connection.stateUpdateHandler = nil
                            default: break
                            }
                        }
                        connection.start(queue: DispatchQueue(label: "tether.direct"))
                        if Task.isCancelled {
                            connection.cancel()
                        }
                    }
                } onCancel: { connection.cancel() }
            }
            return DirectCarrier(connection)
        } catch { connection.cancel(); throw error }
    }

    func send(_ bytes: Data) async throws {
        guard bytes.count <= 65536 else { throw TetherClientError.invalidFrame }
        var length = UInt32(bytes.count).bigEndian
        var frame = withUnsafeBytes(of: &length) { Data($0) }
        frame.append(bytes)
        let connection = connection
        let output = frame
        try await withTetherDeadline {
            try await withTaskCancellationHandler {
                try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
                    connection.send(content: output, completion: .contentProcessed { error in
                        if error != nil {
                            continuation.resume(throwing: TetherClientError.connectionClosed)
                        } else {
                            continuation.resume()
                        }
                    })
                }
            } onCancel: { connection.cancel() }
        }
    }

    func receive() async throws -> Data {
        let connection = connection
        return try await withTetherDeadline(seconds: 60) {
            let header = try await Self.exact(connection, count: 4)
            let length = header.reduce(UInt32(0)) { ($0 << 8) | UInt32($1) }
            guard length <= 65536 else { throw TetherClientError.invalidFrame }
            return try await Self.exact(connection, count: Int(length))
        }
    }

    private static func exact(_ connection: NWConnection, count: Int) async throws -> Data {
        var result = Data()
        while result.count < count {
            let remaining = count - result.count
            let part: Data = try await withTaskCancellationHandler {
                try await withCheckedThrowingContinuation { continuation in
                    connection.receive(minimumIncompleteLength: 1, maximumLength: remaining) { data, _, complete, error in
                        if error != nil || (data?.isEmpty != false && complete) {
                            continuation.resume(throwing: TetherClientError.connectionClosed)
                        } else if let data, !data.isEmpty {
                            continuation.resume(returning: data)
                        } else {
                            continuation.resume(throwing: TetherClientError.connectionClosed)
                        }
                    }
                }
            } onCancel: { connection.cancel() }
            result.append(part)
        }
        return result
    }

    func close() {
        connection.cancel()
    }
}

actor WebSocketCarrier: TetherCarrier {
    private let session: URLSession
    private let socket: URLSessionWebSocketTask
    private init(session: URLSession, socket: URLSessionWebSocketTask) {
        self.session = session; self.socket = socket
    }

    deinit { socket.cancel(with: .goingAway, reason: nil); session.invalidateAndCancel() }

    static func connect(url: URL, appID: String, hostID: String, allowLoopback: Bool) async throws -> WebSocketCarrier {
        guard let parts = URLComponents(url: url, resolvingAgainstBaseURL: false),
              let host = parts.host, !host.isEmpty, parts.user == nil, parts.password == nil, parts.fragment == nil,
              url.absoluteString.utf8.count <= 2048,
              parts.scheme == "wss" || (allowLoopback && parts.scheme == "ws"
                  && ["127.0.0.1", "::1", "[::1]"].contains(host)),
              hostID.utf8.count == 52, hostID.utf8.allSatisfy({ (97 ... 122).contains($0) || (50 ... 55).contains($0) })
        else {
            throw TetherClientError.invalidRoute
        }
        let configuration = URLSessionConfiguration.ephemeral
        configuration.timeoutIntervalForRequest = 15
        configuration.timeoutIntervalForResource = 3600
        configuration.httpShouldSetCookies = false
        configuration.urlCredentialStorage = nil
        configuration.urlCache = nil
        let session = URLSession(configuration: configuration)
        let socket = session.webSocketTask(with: url)
        socket.maximumMessageSize = 65536
        socket.resume()
        let carrier = WebSocketCarrier(session: session, socket: socket)
        do {
            let metadata = try JSONSerialization.data(withJSONObject: ["type": "client", "app_id": appID, "host_id": hostID])
            guard metadata.count <= 2048, let text = String(data: metadata, encoding: .utf8) else {
                throw TetherClientError.invalidFrame
            }
            try await withTetherDeadline {
                try await withTaskCancellationHandler { try await socket.send(.string(text)) }
                    onCancel: { socket.cancel(with: .goingAway, reason: nil) }
            }
            let ready = try await carrier.next(seconds: 15)
            guard case let .string(text) = ready, text.utf8.count <= 2048,
                  let body = text.data(using: .utf8),
                  let json = try JSONSerialization.jsonObject(with: body) as? [String: Any],
                  json["type"] as? String == "ready" else { throw TetherClientError.invalidProtocol }
            return carrier
        } catch { await carrier.close(); throw error }
    }

    func send(_ bytes: Data) async throws {
        guard bytes.count <= 65536 else { throw TetherClientError.invalidFrame }
        let socket = socket
        try await withTetherDeadline {
            try await withTaskCancellationHandler { try await socket.send(.data(bytes)) }
                onCancel: { socket.cancel(with: .goingAway, reason: nil) }
        }
    }

    private func next(seconds: Double) async throws -> URLSessionWebSocketTask.Message {
        let socket = socket
        return try await withTetherDeadline(seconds: seconds) {
            try await withTaskCancellationHandler { try await socket.receive() }
                onCancel: { socket.cancel(with: .goingAway, reason: nil) }
        }
    }

    func receive() async throws -> Data {
        guard case let .data(data) = try await next(seconds: 60), data.count <= 65536 else {
            throw TetherClientError.invalidFrame
        }
        return data
    }

    func close() {
        socket.cancel(with: .goingAway, reason: nil); session.invalidateAndCancel()
    }
}

extension TetherRoute {
    func connect(appID: String, allowLoopback: Bool) async throws -> any TetherCarrier {
        try Task.checkCancellation()
        switch self {
        case let .privateNetwork(host, port): return try await DirectCarrier.connect(host: host, port: port)
        case let .cloud(url, host):
            return try await WebSocketCarrier.connect(url: url, appID: appID, hostID: host, allowLoopback: allowLoopback)
        }
    }
}
