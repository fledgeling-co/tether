import Foundation

/// A pairing flow running in the Rust core (`nearby.begin` or `code.begin`). The core decides
/// what to send and what each reply means; this only carries its records and saves what it asks.
final class TetherFlow: @unchecked Sendable {
    enum Step {
        case send([String: Any]), receive, wait(Int), showCode(String), hostApproved, storePending, discardPending, confirm
        case outcome(String), failed(String)
    }

    private let handle: UInt64
    private init(handle: UInt64) { self.handle = handle }
    deinit { Bridge.destroy(handle) }

    static func begin(_ request: [String: Any]) throws -> (TetherFlow, [Step]) {
        let response = try Bridge.call(request)
        let flow = try TetherFlow(handle: Bridge.handle(response))
        return (flow, try steps(response))
    }

    func receive(_ message: [String: Any], decision: Bool?, now: UInt64) throws -> [Step] {
        try Self.steps(Bridge.call(["command": "flow.receive", "handle": handle, "message": message,
                                    "decision": decision.map { $0 as Any } ?? NSNull(), "now": now]))
    }

    func tick(decision: Bool?, now: UInt64) throws -> [Step] {
        try Self.steps(Bridge.call(["command": "flow.tick", "handle": handle,
                                    "decision": decision.map { $0 as Any } ?? NSNull(), "now": now]))
    }

    /// The code is on screen. The read timer and the undecided read it needs start here.
    func shown(decision: Bool?, now: UInt64) throws -> [Step] {
        try Self.steps(Bridge.call(["command": "flow.shown", "handle": handle,
                                    "decision": decision.map { $0 as Any } ?? NSNull(), "now": now]))
    }

    /// The pending record is saved; a decline up to here still wins and nothing is acknowledged.
    func stored(decision: Bool?) throws -> [Step] {
        try Self.steps(Bridge.call(["command": "flow.stored", "handle": handle,
                                    "decision": decision.map { $0 as Any } ?? NSNull()]))
    }

    private static func steps(_ response: [String: Any]) throws -> [Step] {
        guard let list = response["actions"] as? [[String: Any]] else { throw TetherError.invalidResponse }
        return try list.map { action in
            switch action["do"] as? String {
            case "send":
                guard let message = action["message"] as? [String: Any] else { throw TetherError.invalidResponse }
                return .send(message)
            case "receive": return .receive
            case "wait": return .wait((action["ms"] as? NSNumber)?.intValue ?? 600)
            case "show_code": return .showCode(action["code"] as? String ?? "")
            case "host_approved": return .hostApproved
            case "store_pending": return .storePending
            case "discard_pending": return .discardPending
            case "confirm": return .confirm
            case "outcome": return .outcome(action["outcome"] as? String ?? "")
            case "failed": return .failed(action["code"] as? String ?? "invalid_protocol")
            default: throw TetherError.invalidResponse
            }
        }
    }
}

extension TetherClientError {
    /// The error for a failure code from the core or a host.
    static func from(code: String) -> TetherClientError {
        switch code {
        case "relay_refused", "nearby_closed": .nearbyRefused
        case "paused": .nearbyPaused
        case "busy": .nearbyBusy
        case "already_paired": .pairingExists
        case "peer_revoked": .peerRevoked
        case "pairing_pending": .pairingPending
        case "service_denied": .serviceRefused
        case "service_capacity": .hostCapacity
        case "media_unavailable": .mediaUnavailable
        case "identity_mismatch": .identityMismatch
        case "invalid_route": .invalidRoute
        case "timeout": .timeout
        case "connection_closed": .connectionClosed
        default: .invalidProtocol
        }
    }

    /// The core's name for this error, for looking up its message.
    var code: String {
        switch self {
        case .nearbyRefused: "nearby_closed"
        case .nearbyPaused: "paused"
        case .nearbyBusy: "busy"
        case .pairingExists: "already_paired"
        case .peerRevoked: "peer_revoked"
        case .pairingPending: "pairing_pending"
        case .serviceRefused: "service_denied"
        case .hostCapacity: "service_capacity"
        case .mediaUnavailable: "media_unavailable"
        case .identityMismatch: "identity_mismatch"
        case .invalidRoute: "invalid_route"
        case .timeout: "timeout"
        case .connectionClosed: "connection_closed"
        default: "invalid_protocol"
        }
    }
}

// MARK: - What screens say

/// A button as the core describes it.
public struct TetherButtonModel: Decodable, Equatable, Sendable {
    public let label: String
    public let enabled: Bool
}

/// Six digits for display: two groups, and a version to read aloud digit by digit.
public struct TetherCodeModel: Decodable, Equatable, Sendable {
    public let digits: String
    public let groups: [String]
    public let spoken: String
}

/// The requesting device's sheet during nearby pairing.
public struct TetherNearbyViewModel: Decodable, Equatable, Sendable {
    public let phase: String
    public let title: String
    public internal(set) var message: String
    /// `neutral`, `success` or `warning`.
    public let tone: String
    public let note: String?
    public let code: TetherCodeModel?
    public let expiry: String?
    public let primary: TetherButtonModel?
    public let secondary: TetherButtonModel?
    /// Whether assistive technology should hear the new content.
    public let announce: Bool
    public let busy: Bool
}

/// The host owner's request sheet.
public struct TetherHostRequestViewModel: Decodable, Equatable, Sendable {
    public let title: String
    public let code: TetherCodeModel
    public let message: String
    public let services: String?
    public let note: String?
    public let expiry: String
    public let primary: TetherButtonModel
    public let secondary: TetherButtonModel
}

/// A saved host's connection state.
public struct TetherConnectionStateModel: Decodable, Equatable, Sendable {
    public let state: String
    public let title: String
    public let explanation: String
    /// `neutral`, `success`, `warning` or `danger`.
    public let tone: String
}

/// The typed-code sheet.
public struct TetherPairCodeViewModel: Decodable, Equatable, Sendable {
    public struct Field: Decodable, Equatable, Sendable {
        public let label: String
        public let placeholder: String
        public let valid: Bool
        public let hint: String?
    }

    public let state: String
    public let title: String
    public let message: String
    public let tone: String
    public let field: Field
    public let primary: TetherButtonModel?
    public let secondary: TetherButtonModel?
    public let busy: Bool
    public let announce: Bool
}

/// The words every Tether screen uses, from the Rust core, so Swift, Compose, WinUI and the web
/// say the same thing.
public enum TetherCopy {
    private static func decode<T: Decodable>(_ type: T.Type, _ request: [String: Any]) -> T? {
        guard var response = try? Bridge.call(request) else { return nil }
        response.removeValue(forKey: "ok")
        guard let data = try? JSONSerialization.data(withJSONObject: response) else { return nil }
        return try? JSONDecoder().decode(T.self, from: data)
    }

    /// The sheet for `state`. `deviceName` is what this device is called in copy ("iPhone").
    public static func nearby(_ state: TetherNearbyPairingState, deviceName: String, canApprove: Bool, now: Date = Date()) -> TetherNearbyViewModel? {
        var request: [String: Any] = ["command": "ui.nearby", "device": deviceName]
        switch state {
        case .idle: return nil
        case let .checking(peer): request.merge(["phase": "checking", "peer": peer]) { $1 }
        case let .code(code, peer, incoming, expires, otherApproved):
            request.merge(["phase": "code", "peer": peer, "incoming": incoming, "code": code.digits,
                           "remainingMs": max(0, Int(expires.timeIntervalSince(now) * 1000)),
                           "canApprove": canApprove, "hostApproved": otherApproved]) { $1 }
        case let .waiting(code, peer): request.merge(["phase": "waiting", "peer": peer, "code": code.digits]) { $1 }
        case let .storing(code, peer): request.merge(["phase": "storing", "peer": peer, "code": code.digits]) { $1 }
        case let .connected(peer, _): request.merge(["phase": "connected", "peer": peer]) { $1 }
        case let .declined(peer, byOther): request.merge(["phase": "declined", "peer": peer, "declinedBySelf": !byOther]) { $1 }
        case let .expired(peer): request.merge(["phase": "expired", "peer": peer]) { $1 }
        case let .failed(peer, _): request.merge(["phase": "failed", "peer": peer]) { $1 }
        }
        var view = decode(TetherNearbyViewModel.self, request)
        // A failure's explanation was worked out from the error when it happened.
        if case let .failed(_, message) = state { view?.message = message }
        return view
    }

    public static func hostRequest(name: String, code: String, remainingMs: Int, shownMs: Int, deviceApproved: Bool,
                                   invited: Bool, services: [String]) -> TetherHostRequestViewModel?
    {
        decode(TetherHostRequestViewModel.self, ["command": "ui.host_request", "name": name, "code": code,
                                                  "remainingMs": max(0, remainingMs), "shownMs": max(0, shownMs),
                                                  "deviceApproved": deviceApproved, "invited": invited, "services": services])
    }

    public static func connectionState(_ state: String) -> TetherConnectionStateModel? {
        decode(TetherConnectionStateModel.self, ["command": "ui.connection_state", "state": state])
    }

    public static func pairCode(state: String = "entry", peer: String = "", text: String, error: String? = nil) -> TetherPairCodeViewModel? {
        var request: [String: Any] = ["command": "ui.pair_code", "state": state, "peer": peer, "text": text]
        if let error { request["error"] = error }
        return decode(TetherPairCodeViewModel.self, request)
    }

    /// Fixed copy, keyed as in the core's `view::strings`. Missing keys read as the key itself.
    public static func strings(device: String) -> [String: String] {
        ((try? Bridge.call(["command": "ui.strings", "device": device])) ?? [:]).compactMapValues { $0 as? String }
    }

    /// A plain-language explanation of `error`, naming `peer`.
    public static func message(for error: Error, peer: String) -> String {
        let code = switch error {
        case let error as TetherClientError: error.code
        case let TetherError.refused(code): code
        default: ""
        }
        return message(code: code, peer: peer)
    }

    public static func message(code: String, peer: String) -> String {
        ((try? Bridge.call(["command": "ui.error", "code": code, "peer": peer]))?["message"] as? String)
            ?? "The pairing didn't finish. Nothing was paired."
    }

    /// A label another device chose, safe to show beside a code.
    public static func label(_ raw: String?, fallback: String) -> String {
        ((try? Bridge.call(["command": "ui.label", "text": raw ?? "", "fallback": fallback]))?["text"] as? String) ?? fallback
    }
}
