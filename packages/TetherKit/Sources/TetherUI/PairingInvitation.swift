import Foundation
import TetherKit

/// An invitation is a short-lived bearer secret. Transfer it privately and never log its URL.
public struct TetherPairingInvitation: Codable, Equatable, Sendable {
    public let version: Int
    public let appID: String
    public let route: TetherRoute
    public let code: String
    public let expiresAt: Date

    public init(appID: String, route: TetherRoute, code: String, expiresAt: Date, now: Date = Date()) throws {
        version = 1; self.appID = appID; self.route = route; self.code = code; self.expiresAt = expiresAt
        try validate(expectedAppID: appID, now: now)
    }

    public func url(now: Date = Date()) throws -> URL {
        try validate(expectedAppID: appID, now: now)
        let data = try JSONEncoder().encode(self)
        let encoded = data.base64EncodedString().replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "")
        var parts = URLComponents(); parts.scheme = "tether"; parts.host = "pair"
        parts.queryItems = [URLQueryItem(name: "data", value: encoded)]
        guard let url = parts.url, url.absoluteString.utf8.count <= 4096 else { throw TetherClientError.invalidRoute }
        return url
    }

    public static func decode(_ url: URL, expectedAppID: String, now: Date = Date()) throws -> Self {
        guard url.absoluteString.utf8.count <= 4096,
              let parts = URLComponents(url: url, resolvingAgainstBaseURL: false),
              parts.scheme == "tether", parts.host == "pair", parts.path.isEmpty,
              parts.user == nil, parts.password == nil, parts.port == nil, parts.fragment == nil,
              let items = parts.queryItems, items.count == 1, items[0].name == "data",
              var raw = items[0].value, raw.utf8.count <= 3500,
              raw.allSatisfy({ $0.isASCII && ($0.isLetter || $0.isNumber || $0 == "-" || $0 == "_") })
        else { throw TetherClientError.invalidRoute }
        raw = raw.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        raw += String(repeating: "=", count: (4 - raw.count % 4) % 4)
        guard let data = Data(base64Encoded: raw) else { throw TetherClientError.invalidRoute }
        let value = try JSONDecoder().decode(Self.self, from: data)
        try value.validate(expectedAppID: expectedAppID, now: now)
        return value
    }

    private func validate(expectedAppID: String, now: Date) throws {
        guard version == 1, appID == expectedAppID, !appID.isEmpty, appID.utf8.count <= 64,
              appID.allSatisfy({ $0.isASCII && ($0.isLetter || $0.isNumber || "._-".contains($0)) }),
              code.count == 8, code.allSatisfy({ "0123456789ABCDEFGHJKMNPQRSTVWXYZ".contains($0) }),
              expiresAt > now, expiresAt.timeIntervalSince(now) <= 301 else { throw TetherClientError.invalidProtocol }
        try TetherPairingFields.validate(route)
    }
}

public enum TetherPairingFields {
    public static func privateRoute(address: String, port: String) throws -> TetherRoute {
        guard let port = UInt16(port), port > 0 else { throw TetherClientError.invalidRoute }
        let route = TetherRoute.privateNetwork(host: address.trimmingCharacters(in: .whitespacesAndNewlines), port: port)
        try validate(route); return route
    }
    public static func cloudRoute(relay: String, hostID: String) throws -> TetherRoute {
        guard let url = URL(string: relay.trimmingCharacters(in: .whitespacesAndNewlines)) else { throw TetherClientError.invalidRoute }
        let route = TetherRoute.cloud(relayURL: url, hostID: hostID.trimmingCharacters(in: .whitespacesAndNewlines))
        try validate(route); return route
    }
    public static func validate(_ route: TetherRoute) throws {
        switch route {
        case let .privateNetwork(host, port):
            guard port > 0, !host.isEmpty, host.utf8.count <= 320,
                  host != "0.0.0.0", host != "::", host != "[::]",
                  !host.contains(where: { $0.isWhitespace || "/?#@".contains($0) }) else { throw TetherClientError.invalidRoute }
        case let .cloud(url, hostID):
            guard let p = URLComponents(url: url, resolvingAgainstBaseURL: false), p.scheme == "wss",
                  p.host?.isEmpty == false, p.user == nil, p.password == nil, p.query == nil, p.fragment == nil,
                  url.absoluteString.utf8.count <= 2048, hostID.count == 52,
                  hostID.allSatisfy({ "abcdefghijklmnopqrstuvwxyz234567".contains($0) }) else { throw TetherClientError.invalidRoute }
        }
    }
}
