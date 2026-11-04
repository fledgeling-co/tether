import Foundation

public struct TetherMediaStatistics: Codable, Equatable, Sendable {
    public let roundTripMilliseconds: Double
    public let bytesSent: UInt64
    public let bytesReceived: UInt64
    public let packetsSent: UInt64
    public let packetsReceived: UInt64
    public let dropped: UInt64
    enum CodingKeys: String, CodingKey {
        case roundTripMilliseconds = "rtt_ms"
        case bytesSent = "bytes_sent"
        case bytesReceived = "bytes_received"
        case packetsSent = "packets_sent"
        case packetsReceived = "packets_received"
        case dropped
    }
}

enum MediaNativeState: Sendable { case connecting, ready(Int), failed, closed }
enum MediaNativeReceive: Sendable { case pending, data(Data), closed, failed }
protocol MediaBackend: Sendable {
    func poll(_ handle: UInt64) async throws -> MediaNativeState
    func send(_ data: Data, handle: UInt64) async throws -> Bool
    func receive(_ handle: UInt64) async throws -> MediaNativeReceive
    func statistics(_ handle: UInt64) async throws -> TetherMediaStatistics
    func close(_ handle: UInt64) async
}

struct MediaOffer: Decodable, Sendable {
    let lease_id: Data
    let token: Data
    let cert_pin: Data
    let port: UInt16
    let max_datagram: Int
    let heartbeat_seconds: Int
    let lease_ttl_seconds: Int
    func validate() throws {
        guard lease_id.count == 16, token.count == 32, cert_pin.count == 32, port != 0,
              (1 ... 1200).contains(max_datagram), heartbeat_seconds == 2, lease_ttl_seconds == 5
        else {
            throw TetherClientError.invalidProtocol
        }
    }
}

/// Connection work runs in the native runtime. Packet receives use a bounded native wait on
/// a dedicated blocking queue; other calls are nonblocking. Close wakes the receive waiter.
actor RustMediaBackend: MediaBackend {
    private let receiver = DispatchQueue(label: "tether.media.receive", qos: .userInitiated)
    func start(address: String, offer: MediaOffer) throws -> UInt64 {
        let response = try Bridge.call(["command": "media.client.start", "address": address, "port": offer.port,
                                        "cert_pin": offer.cert_pin.base64EncodedString(),
                                        "lease_id": offer.lease_id.base64EncodedString(), "token": offer.token.base64EncodedString()])
        return try Bridge.handle(response)
    }

    private struct Poll: Decodable { let state: String; let max_datagram: Int? }
    func poll(_ handle: UInt64) throws -> MediaNativeState {
        let response: Poll = try decode(Bridge.call(["command": "media.poll", "handle": handle]))
        switch response.state {
        case "connecting": return .connecting
        case "ready":
            guard let size = response.max_datagram, (1 ... 1200).contains(size) else { throw TetherClientError.invalidProtocol }
            return .ready(size)
        case "failed": return .failed
        case "closed": return .closed
        default: throw TetherClientError.invalidProtocol
        }
    }

    func send(_ data: Data, handle: UInt64) throws -> Bool {
        do {
            let response = try Bridge.call(["command": "media.send", "handle": handle, "data": data.base64EncodedString()])
            guard response["accepted"] as? Bool == true else { throw TetherClientError.invalidProtocol }
            return true
        } catch TetherError.refused("media_backpressure") { return false }
    }

    private struct Receive: Decodable { let state: String; let data: Data? }
    func receive(_ handle: UInt64) async throws -> MediaNativeReceive {
        try Task.checkCancellation()
        let receiver = receiver
        return try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { continuation in
                guard !Task.isCancelled else { continuation.resume(throwing: CancellationError()); return }
                // Native receive_wait uses a bounded Condvar wait on this dedicated blocking
                // queue. Packet/close wakes it immediately; no cooperative executor is blocked.
                receiver.async {
                    do {
                        let value = try Bridge.call(["command": "media.receive_wait", "handle": handle, "timeout_ms": 100])
                        try continuation.resume(returning: Self.receiveResult(value))
                    } catch { continuation.resume(throwing: error) }
                }
            }
        } onCancel: {
            // This operation is nonblocking and wakes receive_wait on its caller thread.
            _ = try? Bridge.call(["command": "media.close", "handle": handle])
        }
    }

    private static func receiveResult(_ value: [String: Any]) throws -> MediaNativeReceive {
        let response = try JSONDecoder().decode(Receive.self, from: JSONSerialization.data(withJSONObject: value))
        switch response.state {
        case "pending": return .pending
        case "data":
            guard let bytes = response.data else { throw TetherClientError.invalidProtocol }
            return .data(bytes)
        case "closed": return .closed
        case "failed": return .failed
        default: throw TetherClientError.invalidProtocol
        }
    }

    func statistics(_ handle: UInt64) throws -> TetherMediaStatistics {
        let result: TetherMediaStatistics = try decode(Bridge.call(["command": "media.stats", "handle": handle]))
        guard result.roundTripMilliseconds.isFinite, result.roundTripMilliseconds >= 0 else {
            throw TetherClientError.invalidProtocol
        }
        return result
    }

    func close(_ handle: UInt64) {
        _ = try? Bridge.call(["command": "media.close", "handle": handle])
    }

    private func decode<T: Decodable>(_ value: [String: Any]) throws -> T {
        try JSONDecoder().decode(T.self, from: JSONSerialization.data(withJSONObject: value))
    }
}
