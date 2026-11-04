import Foundation

/// Public display names only. Identity keys, pairing codes and application data never enter this store.
public protocol TetherHostMetadataPersistence: Sendable {
    func name(appID: String, hostKey: Data) async -> String?
    func setName(_ name: String, appID: String, hostKey: Data) async
}

public actor TetherUserDefaultsHostMetadata: TetherHostMetadataPersistence {
    private let defaults: UserDefaults
    public init(suiteName: String? = nil) {
        defaults = suiteName.flatMap(UserDefaults.init(suiteName:)) ?? .standard
    }

    public func name(appID: String, hostKey: Data) -> String? {
        defaults.string(forKey: key(appID, hostKey))
    }

    public func setName(_ name: String, appID: String, hostKey: Data) {
        defaults.set(name, forKey: key(appID, hostKey))
    }

    private func key(_ app: String, _ host: Data) -> String {
        "tether.host-name.v1." + app + "." + host.base64EncodedString()
    }
}
