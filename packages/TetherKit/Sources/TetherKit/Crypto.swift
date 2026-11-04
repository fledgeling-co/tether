import Foundation

public struct TetherNoiseMetadata: Sendable {
    public let binding: Data
    public let remoteStatic: Data?
    public let finished: Bool
    init(_ response: [String: Any]) throws {
        binding = try Bridge.data(response, "binding", count: 32)
        if response["remoteStatic"] is String {
            remoteStatic = try Bridge.data(response, "remoteStatic", count: 32)
        } else {
            remoteStatic = nil
        }
        finished = response["finished"] as? Bool ?? false
    }
}

public actor TetherNoise {
    private var handle: UInt64?
    public private(set) var metadata: TetherNoiseMetadata?
    public init(identity: TetherIdentity, appID: String, role: TetherRole) throws {
        guard identity.appID == appID else { throw TetherError.invalidScope }
        handle = try Bridge.handle(Bridge.call([
            "command": "noise.new", "identity": identity.handle, "app": appID, "role": role.rawValue,
        ]))
    }

    deinit { Bridge.destroy(handle) }
    public func write() throws -> Data {
        try message("noise.write", data: Data())
    }

    public func read(_ data: Data) throws {
        _ = try message("noise.read", data: data)
    }

    private func message(_ command: String, data: Data) throws -> Data {
        guard let handle else { throw TetherError.closed }
        do {
            let response = try Bridge.call(["command": command, "handle": handle, "data": data.base64EncodedString()])
            metadata = try TetherNoiseMetadata(response)
            return try Bridge.data(response)
        } catch { Bridge.destroy(handle); self.handle = nil; throw error }
    }

    public func finish() throws -> TetherSecureTransport {
        guard let handle else { throw TetherError.closed }
        self.handle = nil
        return try TetherSecureTransport(response: Bridge.call(["command": "noise.finish", "handle": handle]))
    }

    public func close() {
        Bridge.destroy(handle); handle = nil
    }
}

/// Callers authenticate/pin both peer statics before forwarding application service data.
public actor TetherSecureTransport {
    private var handle: UInt64?
    public nonisolated let metadata: TetherNoiseMetadata
    init(response: [String: Any]) throws {
        let id = try Bridge.handle(response)
        do {
            let observed = try TetherNoiseMetadata(response)
            guard observed.finished else { throw TetherError.invalidResponse }
            metadata = observed
        } catch { Bridge.destroy(id); throw error }
        handle = id
    }

    deinit { Bridge.destroy(handle) }
    public func encrypt(_ data: Data) throws -> Data {
        try message("transport.encrypt", data: data)
    }

    public func decrypt(_ data: Data) throws -> Data {
        try message("transport.decrypt", data: data)
    }

    private func message(_ command: String, data: Data) throws -> Data {
        guard let handle else { throw TetherError.closed }
        do {
            return try Bridge.data(Bridge.call([
                "command": command, "handle": handle, "data": data.base64EncodedString(),
            ]))
        } catch { Bridge.destroy(handle); self.handle = nil; throw error }
    }

    public func close() {
        Bridge.destroy(handle); handle = nil
    }
}

public actor TetherPairing {
    private var handle: UInt64?
    public nonisolated let message: Data
    public init(role: TetherRole, code: String, appID: String, binding: Data, clientKey: Data, hostKey: Data) throws {
        let response = try Bridge.call([
            "command": "pairing.start", "role": role.rawValue, "code": code, "app": appID,
            "binding": binding.base64EncodedString(), "clientKey": clientKey.base64EncodedString(),
            "hostKey": hostKey.base64EncodedString(),
        ])
        let id = try Bridge.handle(response)
        do { message = try Bridge.data(response, count: 33) }
        catch { Bridge.destroy(id); throw error }
        handle = id
    }

    deinit { Bridge.destroy(handle) }
    public func finish(_ peer: Data) throws -> TetherConfirmation {
        guard let handle else { throw TetherError.closed }
        self.handle = nil
        return try TetherConfirmation(response: Bridge.call([
            "command": "pairing.finish", "handle": handle, "data": peer.base64EncodedString(),
        ]))
    }

    public func close() {
        Bridge.destroy(handle); handle = nil
    }
}

public actor TetherConfirmation {
    private var handle: UInt64?
    public nonisolated let outbound: Data
    init(response: [String: Any]) throws {
        let id = try Bridge.handle(response)
        do { outbound = try Bridge.data(response, count: 32) }
        catch { Bridge.destroy(id); throw error }
        handle = id
    }

    deinit { Bridge.destroy(handle) }
    public func verify(_ peer: Data) throws {
        guard let handle else { throw TetherError.closed }
        self.handle = nil
        _ = try Bridge.call(["command": "pairing.verify", "handle": handle, "data": peer.base64EncodedString()])
    }

    public func close() {
        Bridge.destroy(handle); handle = nil
    }
}
