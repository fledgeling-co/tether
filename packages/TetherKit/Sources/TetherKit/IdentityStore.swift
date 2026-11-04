import Foundation
import Security

public protocol TetherIdentityPersistence: Sendable {
    func load(appID: String) async throws -> Data?
    func save(_ privateKey: Data, appID: String) async throws
}

/// Every application has a separate account and key. No synchronizable/shared global identity.
public actor TetherKeychainPersistence: TetherIdentityPersistence {
    private let service: String
    public init(service: String = "app.fledgeling.tether.identity.v1") {
        self.service = service
    }

    private func query(_ appID: String) -> [String: Any] {
        [kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: service,
         kSecAttrAccount as String: appID, kSecAttrSynchronizable as String: false,
         kSecUseDataProtectionKeychain as String: true]
    }

    public func load(appID: String) throws -> Data? {
        var query = query(appID)
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        if status == errSecItemNotFound {
            return nil
        }
        guard status == errSecSuccess, let data = item as? Data else {
            throw TetherError.keychain(status)
        }
        return data
    }

    public func save(_ privateKey: Data, appID: String) throws {
        var query = query(appID)
        query[kSecValueData as String] = privateKey
        query[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        let status = SecItemAdd(query as CFDictionary, nil)
        // Fail rather than overwrite an identity concurrently installed by another process.
        guard status == errSecSuccess else { throw TetherError.keychain(status) }
    }
}

public actor TetherIdentityStore {
    private let persistence: any TetherIdentityPersistence
    private var identities: [String: TetherIdentity] = [:]
    private var pending: [String: Task<TetherIdentity, Error>] = [:]
    public init(persistence: any TetherIdentityPersistence = TetherKeychainPersistence()) {
        self.persistence = persistence
    }

    public func identity(appID: String) async throws -> TetherIdentity {
        try Bridge.validateScope(appID)
        if let identity = identities[appID] {
            return identity
        }
        if let task = pending[appID] {
            return try await task.value
        }
        let persistence = persistence
        let task = Task<TetherIdentity, Error> {
            if var stored = try await persistence.load(appID: appID) {
                defer { stored.resetBytes(in: stored.startIndex ..< stored.endIndex) }
                return try TetherIdentity(response: Bridge.call([
                    "command": "identity.fromPrivate", "private": stored.base64EncodedString(),
                ]), appID: appID)
            }
            let response = try Bridge.call(["command": "identity.generate"])
            let identity = try TetherIdentity(response: response, appID: appID)
            var privateKey = try Bridge.data(response, "private")
            defer { privateKey.resetBytes(in: privateKey.startIndex ..< privateKey.endIndex) }
            do {
                try await persistence.save(privateKey, appID: appID)
                return identity
            } catch {
                // Another process may have won the Keychain add; adopt its actual stored key.
                if var installed = try await persistence.load(appID: appID) {
                    defer { installed.resetBytes(in: installed.startIndex ..< installed.endIndex) }
                    return try TetherIdentity(response: Bridge.call([
                        "command": "identity.fromPrivate", "private": installed.base64EncodedString(),
                    ]), appID: appID)
                }
                throw error
            }
        }
        pending[appID] = task
        do {
            let identity = try await task.value
            identities[appID] = identity
            pending[appID] = nil
            return identity
        } catch {
            pending[appID] = nil
            throw error
        }
    }
}
