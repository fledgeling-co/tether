import Foundation
import TetherFFI

public enum TetherError: Error, Sendable {
    case invalidResponse
    case refused(String)
    case invalidScope
    case keychain(Int32)
    case closed
}

public enum TetherRole: String, Sendable { case client, host }

enum Bridge {
    static func call(_ request: [String: Any]) throws -> [String: Any] {
        var bytes = try JSONSerialization.data(withJSONObject: request)
        defer { bytes.resetBytes(in: bytes.startIndex ..< bytes.endIndex) }
        let response = bytes.withUnsafeBytes { raw -> UnsafeMutablePointer<CChar>? in
            tether_call(raw.bindMemory(to: UInt8.self).baseAddress, raw.count)
        }
        guard let response else { throw TetherError.invalidResponse }
        defer { tether_free(response) }
        // Never log this JSON: identity operations contain the private Keychain value.
        var data = Data(bytes: response, count: strlen(response))
        defer { data.resetBytes(in: data.startIndex ..< data.endIndex) }
        guard let result = try JSONSerialization.jsonObject(with: data) as? [String: Any],
              let ok = result["ok"] as? Bool else { throw TetherError.invalidResponse }
        guard ok else {
            let code = result["error"] as? String ?? "operation_refused"
            throw TetherError.refused(String(code.prefix(64)))
        }
        return result
    }

    static func handle(_ response: [String: Any]) throws -> UInt64 {
        guard let handle = response["handle"] as? NSNumber, handle.uint64Value != 0 else {
            throw TetherError.invalidResponse
        }
        return handle.uint64Value
    }

    static func data(_ response: [String: Any], _ key: String = "data", count: Int? = nil) throws -> Data {
        guard let value = response[key] as? String, let data = Data(base64Encoded: value) else {
            throw TetherError.invalidResponse
        }
        guard count == nil || data.count == count else { throw TetherError.invalidResponse }
        return data
    }

    static func destroy(_ handle: UInt64?) {
        if let handle {
            _ = try? call(["command": "destroy", "handle": handle])
        }
    }

    static func validateScope(_ appID: String) throws {
        guard !appID.isEmpty, appID.utf8.count <= 64,
              appID.utf8.allSatisfy({ (48 ... 57).contains($0) || (65 ... 90).contains($0)
                      || (97 ... 122).contains($0) || [45, 46, 95].contains($0) })
        else {
            throw TetherError.invalidScope
        }
    }
}

/// Immutable local ownership of a Rust identity handle; no private key is exposed by this type.
public final class TetherIdentity: Sendable {
    let handle: UInt64
    public let publicKey: Data
    public let appID: String
    init(response: [String: Any], appID: String) throws {
        let id = try Bridge.handle(response)
        do {
            publicKey = try Bridge.data(response, "public", count: 32)
        } catch { Bridge.destroy(id); throw error }
        handle = id
        self.appID = appID
    }

    deinit { Bridge.destroy(handle) }
}
