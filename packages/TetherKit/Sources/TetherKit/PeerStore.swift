import Foundation
import Security

public struct TetherPeerRecord: Codable, Equatable, Sendable {
    public let appID: String
    public let hostKey: Data
    public let clientKey: Data
    public let route: TetherRoute
    public let confirmed: Bool
    public let pairingID: UUID
    init(appID: String, hostKey: Data, clientKey: Data, route: TetherRoute, confirmed: Bool,
         pairingID: UUID = UUID())
    {
        self.appID = appID; self.hostKey = hostKey; self.clientKey = clientKey
        self.route = route; self.confirmed = confirmed
        self.pairingID = pairingID
    }
}

public protocol TetherPeerPersistence: Sendable {
    func list(appID: String) async throws -> [Data]
    func load(appID: String, hostKey: Data) async throws -> Data?
    func save(_ value: Data, appID: String, hostKey: Data, createOnly: Bool) async throws
    func discardPending(appID: String, hostKey: Data, pairingID: UUID) async throws
    func removeConfirmed(appID: String, hostKey: Data, pairingID: UUID) async throws
    func replaceConfirmed(_ value: Data, appID: String, hostKey: Data, expectedPairingID: UUID) async throws
}

/// Custom stores must atomically match the confirmed generation when removing or replacing trust.
/// Defaults refuse both operations so older adapters cannot silently weaken this boundary.
/// Actor adapters should declare these methods async explicitly so concrete actor calls cannot
/// select an async default overload instead of the adapter's synchronous actor method.
public extension TetherPeerPersistence {
    func replaceConfirmed(_: Data, appID _: String, hostKey _: Data, expectedPairingID _: UUID) async throws {
        throw TetherError.invalidScope
    }

    func removeConfirmed(appID _: String, hostKey _: Data, pairingID _: UUID) async throws {
        throw TetherError.invalidScope
    }
}

/// Both route and peer pins live in this-device-only Keychain items, apart from identity keys.
public actor TetherKeychainPeerPersistence: TetherPeerPersistence {
    private let service: String
    public init(service: String = "app.fledgeling.tether.peers.v1") {
        self.service = service
    }

    private func query(appID: String, hostKey: Data) -> [String: Any] {
        [kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: service,
         kSecAttrAccount as String: appID + "|" + hostKey.base64EncodedString(),
         kSecAttrSynchronizable as String: false, kSecUseDataProtectionKeychain as String: true]
    }

    public func list(appID: String) throws -> [Data] {
        let query: [String: Any] = [kSecClass as String: kSecClassGenericPassword,
                                    kSecAttrService as String: service, kSecAttrSynchronizable as String: false,
                                    kSecUseDataProtectionKeychain as String: true, kSecReturnData as String: true,
                                    kSecReturnAttributes as String: true, kSecMatchLimit as String: kSecMatchLimitAll]
        var value: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &value)
        if status == errSecItemNotFound {
            return []
        }
        guard status == errSecSuccess else { throw TetherError.keychain(status) }
        guard let items = value as? [[String: Any]] else { throw TetherError.invalidResponse }
        return items.compactMap { item in
            guard let account = item[kSecAttrAccount as String] as? String,
                  account.hasPrefix(appID + "|") else { return nil }
            return item[kSecValueData as String] as? Data
        }
    }

    public func load(appID: String, hostKey: Data) throws -> Data? {
        var query = query(appID: appID, hostKey: hostKey)
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        var value: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &value)
        if status == errSecItemNotFound {
            return nil
        }
        guard status == errSecSuccess, let data = value as? Data else { throw TetherError.keychain(status) }
        return data
    }

    public func save(_ value: Data, appID: String, hostKey: Data, createOnly: Bool) throws {
        guard value.count <= 8192 else { throw TetherError.invalidResponse }
        var query = query(appID: appID, hostKey: hostKey)
        let record = try JSONDecoder().decode(TetherPeerRecord.self, from: value)
        guard record.appID == appID, record.hostKey == hostKey else { throw TetherError.invalidScope }
        let marker = marker(record)
        guard createOnly != record.confirmed else { throw TetherClientError.pairingPending }
        let status: OSStatus
        if createOnly {
            query[kSecAttrGeneric as String] = marker
            query[kSecValueData as String] = value
            query[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
            status = SecItemAdd(query as CFDictionary, nil)
        } else {
            query[kSecAttrGeneric as String] = Data(("tether-pending-v1|" + record.pairingID.uuidString).utf8)
            status = SecItemUpdate(query as CFDictionary,
                                   [kSecValueData as String: value, kSecAttrGeneric as String: marker] as CFDictionary)
        }
        guard status == errSecSuccess else { throw TetherError.keychain(status) }
    }

    private func marker(_ record: TetherPeerRecord) -> Data {
        Data(((record.confirmed ? "tether-confirmed-v1|" : "tether-pending-v1|") + record.pairingID.uuidString).utf8)
    }

    public func discardPending(appID: String, hostKey: Data, pairingID: UUID) throws {
        var query = query(appID: appID, hostKey: hostKey)
        // Match the pending marker inside SecItemDelete itself. A concurrent confirmation
        // atomically changes it, so this operation cannot delete a newly confirmed record.
        query[kSecAttrGeneric as String] = Data(("tether-pending-v1|" + pairingID.uuidString).utf8)
        let status = SecItemDelete(query as CFDictionary)
        guard status == errSecSuccess else { throw TetherError.keychain(status) }
    }

    public func replaceConfirmed(_ value: Data, appID: String, hostKey: Data, expectedPairingID: UUID) async throws {
        guard value.count <= 8192 else { throw TetherError.invalidResponse }
        let record = try JSONDecoder().decode(TetherPeerRecord.self, from: value)
        guard record.appID == appID, record.hostKey == hostKey, record.confirmed,
              record.pairingID != expectedPairingID else { throw TetherError.invalidScope }
        var query = query(appID: appID, hostKey: hostKey)
        query[kSecAttrGeneric as String] = Data(("tether-confirmed-v1|" + expectedPairingID.uuidString).utf8)
        let status = SecItemUpdate(query as CFDictionary,
                                   [kSecValueData as String: value, kSecAttrGeneric as String: marker(record)] as CFDictionary)
        guard status == errSecSuccess else { throw TetherError.keychain(status) }
    }

    public func removeConfirmed(appID: String, hostKey: Data, pairingID: UUID) async throws {
        var query = query(appID: appID, hostKey: hostKey)
        query[kSecAttrGeneric as String] = Data(("tether-confirmed-v1|" + pairingID.uuidString).utf8)
        let status = SecItemDelete(query as CFDictionary)
        guard status == errSecSuccess else { throw TetherError.keychain(status) }
    }
}

public actor TetherPeerStore {
    private let persistence: any TetherPeerPersistence
    public init(persistence: any TetherPeerPersistence = TetherKeychainPeerPersistence()) {
        self.persistence = persistence
    }

    public func records(appID: String) async throws -> [TetherPeerRecord] {
        try Bridge.validateScope(appID)
        return try await persistence.list(appID: appID).map { data in
            let record = try decode(data)
            guard record.appID == appID else { throw TetherError.invalidScope }
            return record
        }
    }

    func record(appID: String, hostKey: Data) async throws -> TetherPeerRecord? {
        guard let data = try await persistence.load(appID: appID, hostKey: hostKey) else { return nil }
        let record = try decode(data)
        guard record.appID == appID, record.hostKey == hostKey else { throw TetherError.invalidScope }
        return record
    }

    func begin(_ record: TetherPeerRecord) async throws {
        guard try await self.record(appID: record.appID, hostKey: record.hostKey) == nil else {
            throw TetherClientError.pairingExists
        }
        try await persistence.save(JSONEncoder().encode(record), appID: record.appID,
                                   hostKey: record.hostKey, createOnly: true)
    }

    func confirm(_ record: TetherPeerRecord) async throws -> TetherPeerRecord {
        guard let current = try await self.record(appID: record.appID, hostKey: record.hostKey),
              current.clientKey == record.clientKey, current.route == record.route,
              current.pairingID == record.pairingID
        else {
            throw TetherClientError.pairingPending
        }
        if current.confirmed {
            return current
        }
        let confirmed = TetherPeerRecord(appID: current.appID, hostKey: current.hostKey,
                                         clientKey: current.clientKey, route: current.route, confirmed: true,
                                         pairingID: current.pairingID)
        try await persistence.save(JSONEncoder().encode(confirmed), appID: record.appID,
                                   hostKey: record.hostKey, createOnly: false)
        return confirmed
    }

    func discardPending(_ record: TetherPeerRecord) async throws {
        guard !record.confirmed,
              let current = try await self.record(appID: record.appID, hostKey: record.hostKey),
              !current.confirmed, current == record else { throw TetherClientError.pairingExists }
        try await persistence.discardPending(appID: record.appID, hostKey: record.hostKey, pairingID: record.pairingID)
    }

    func replaceRoute(_ record: TetherPeerRecord, route: TetherRoute) async throws -> TetherPeerRecord {
        guard record.confirmed, try await self.record(appID: record.appID, hostKey: record.hostKey) == record else {
            throw TetherClientError.identityMismatch
        }
        let replacement = TetherPeerRecord(appID: record.appID, hostKey: record.hostKey, clientKey: record.clientKey,
                                           route: route, confirmed: true)
        try await persistence.replaceConfirmed(JSONEncoder().encode(replacement), appID: record.appID,
                                               hostKey: record.hostKey, expectedPairingID: record.pairingID)
        return replacement
    }

    func removeConfirmed(_ record: TetherPeerRecord) async throws {
        guard record.confirmed,
              let current = try await self.record(appID: record.appID, hostKey: record.hostKey),
              current == record else { throw TetherClientError.identityMismatch }
        try await persistence.removeConfirmed(appID: record.appID, hostKey: record.hostKey,
                                              pairingID: record.pairingID)
    }

    private func decode(_ data: Data) throws -> TetherPeerRecord {
        guard data.count <= 8192 else { throw TetherError.invalidResponse }
        let record = try JSONDecoder().decode(TetherPeerRecord.self, from: data)
        try Bridge.validateScope(record.appID)
        guard record.hostKey.count == 32, record.clientKey.count == 32 else { throw TetherError.invalidResponse }
        return record
    }
}
