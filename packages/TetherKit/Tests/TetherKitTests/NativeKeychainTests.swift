#if os(macOS) || os(iOS)
    import Foundation
    import LocalAuthentication
    import Security
    import Testing
    @testable import TetherKit

    @Suite("Opt-in native Keychain metadata predicates")
    struct NativeKeychainTests {
        private struct NativeUnavailable: Error {
            let status: OSStatus
        }

        private func query(service: String, account: String) -> [String: Any] {
            let context = LAContext()
            context.interactionNotAllowed = true
            return [kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: service,
                    kSecAttrAccount as String: account, kSecAttrSynchronizable as String: false,
                    kSecUseDataProtectionKeychain as String: true,
                    kSecUseAuthenticationContext as String: context]
        }

        @Test(.enabled(if: ProcessInfo.processInfo.environment["TETHER_TEST_REAL_KEYCHAIN"] == "1"
                && Bundle.main.bundleIdentifier?.hasPrefix("app.fledgeling.tether.validation") == true))
        func isolatedNativeCrudAndGenerationPredicates() async throws {
            let namespace = UUID().uuidString.lowercased()
            let identityService = "test.tether.fixture." + namespace + ".identity"
            let peerService = "test.tether.fixture." + namespace + ".peers"
            let appA = "test.tether." + namespace + ".a"
            let appB = "test.tether." + namespace + ".b"
            let appHost = "test.tether." + namespace + ".host"
            let probe = "probe"
            var accounts = [(identityService, probe), (identityService, appA), (identityService, appB),
                            (identityService, appHost)]
            var phases: [String] = []
            var preflightStatus: OSStatus = errSecSuccess
            defer {
                var cleanupErrors: [Int32] = []
                var absentCount = 0
                for (service, account) in accounts {
                    let exact = query(service: service, account: account)
                    let deleted = SecItemDelete(exact as CFDictionary)
                    if deleted != errSecSuccess, deleted != errSecItemNotFound {
                        cleanupErrors.append(deleted)
                    }
                    let absent = SecItemCopyMatching(exact as CFDictionary, nil)
                    if absent == errSecItemNotFound {
                        absentCount += 1
                    } else if preflightStatus == errSecSuccess {
                        Issue.record("a test-owned Keychain item was not absent after cleanup")
                    }
                }
                let evidence: [String: Any] = ["preflightStatus": preflightStatus, "phases": phases,
                                               "scopedAccounts": accounts.count, "verifiedAbsent": absentCount, "cleanupErrors": cleanupErrors]
                let documentsPath = ProcessInfo.processInfo.environment["TETHER_KEYCHAIN_TEST_EVIDENCE_DOCUMENTS"] == "1"
                    ? FileManager.default.urls(for: .documentDirectory, in: .userDomainMask).first?
                    .appendingPathComponent("tether-keychain-fixture-evidence.json").path : nil
                if let path = ProcessInfo.processInfo.environment["TETHER_KEYCHAIN_TEST_EVIDENCE"] ?? documentsPath,
                   let data = try? JSONSerialization.data(withJSONObject: evidence, options: [.sortedKeys])
                {
                    FileManager.default.createFile(atPath: path, contents: data, attributes: [.posixPermissions: 0o600])
                }
            }
            // Never trigger or approve an authentication prompt. If an unlocked, entitled context
            // cannot create its own fresh item noninteractively, the native gate remains unmeasured.
            var preflight = query(service: identityService, account: probe)
            preflight[kSecValueData as String] = Data("synthetic-probe".utf8)
            preflight[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
            preflightStatus = SecItemAdd(preflight as CFDictionary, nil)
            guard preflightStatus == errSecSuccess else { throw NativeUnavailable(status: preflightStatus) }
            phases.append("noninteractive-owned-item-created")

            let identityPersistence = TetherKeychainPersistence(service: identityService)
            let identities = TetherIdentityStore(persistence: identityPersistence)
            let a = try await identities.identity(appID: appA)
            let b = try await identities.identity(appID: appB)
            let host = try await identities.identity(appID: appHost)
            #expect(a.publicKey != b.publicKey)
            let reopened = TetherIdentityStore(persistence: identityPersistence)
            #expect(try await reopened.identity(appID: appA).publicKey == a.publicKey)
            #expect(try await identityPersistence.load(appID: appA)?.count == 32)
            phases.append("real-identities-scoped-and-reopened")

            accounts.append((peerService, appA + "|" + host.publicKey.base64EncodedString()))
            let persistence = TetherKeychainPeerPersistence(service: peerService)
            let peers = TetherPeerStore(persistence: persistence)
            let pending = TetherPeerRecord(appID: appA, hostKey: host.publicKey, clientKey: a.publicKey,
                                           route: .privateNetwork(host: "127.0.0.1", port: 7445), confirmed: false)
            try await peers.begin(pending)
            #expect(try await peers.records(appID: appA) == [pending])
            #expect(try await peers.records(appID: appB).isEmpty)
            phases.append("real-pending-record-scoped")
            // Wrong generation must never delete even the pending record.
            do {
                try await persistence.discardPending(appID: appA, hostKey: host.publicKey, pairingID: UUID())
                Issue.record("a wrong pending generation deleted a Keychain item")
            } catch TetherError.keychain(errSecItemNotFound) {}
            #expect(try await peers.records(appID: appA) == [pending])
            let confirmed = try await peers.confirm(pending)
            #expect(confirmed.confirmed)
            #expect(try await peers.records(appID: appA) == [confirmed])
            do {
                try await persistence.discardPending(appID: appA, hostKey: host.publicKey, pairingID: pending.pairingID)
                Issue.record("a stale pending delete removed a confirmed Keychain item")
            } catch TetherError.keychain(errSecItemNotFound) {}
            #expect(try await peers.records(appID: appA) == [confirmed])
            phases.append("real-confirmation-and-stale-delete-refusal")

            // Confirmed removal uses its own atomic generation marker. A late operation from the
            // previous pairing cannot remove replacement confirmed trust for this same app/host.
            do {
                try await persistence.removeConfirmed(appID: appA, hostKey: host.publicKey, pairingID: UUID())
                Issue.record("wrong confirmed generation removed a Keychain item")
            } catch TetherError.keychain(errSecItemNotFound) {}
            try await peers.removeConfirmed(confirmed)
            let nextPending = TetherPeerRecord(appID: appA, hostKey: host.publicKey, clientKey: a.publicKey,
                                               route: pending.route, confirmed: false)
            try await peers.begin(nextPending)
            let nextConfirmed = try await peers.confirm(nextPending)
            do {
                try await persistence.removeConfirmed(appID: appA, hostKey: host.publicKey, pairingID: confirmed.pairingID)
                Issue.record("stale confirmed generation removed replacement Keychain trust")
            } catch TetherError.keychain(errSecItemNotFound) {}
            #expect(try await peers.records(appID: appA) == [nextConfirmed])
            let routed = try await peers.replaceRoute(nextConfirmed, route: .privateNetwork(host: "127.0.0.1", port: 7446))
            #expect(routed.pairingID != nextConfirmed.pairingID)
            let staleCandidate = TetherPeerRecord(appID: appA, hostKey: host.publicKey, clientKey: a.publicKey,
                                                  route: nextConfirmed.route, confirmed: true)
            do {
                try await persistence.replaceConfirmed(JSONEncoder().encode(staleCandidate), appID: appA,
                                                       hostKey: host.publicKey, expectedPairingID: nextConfirmed.pairingID)
                Issue.record("stale route CAS replaced current Keychain trust")
            } catch TetherError.keychain(errSecItemNotFound) {}
            do {
                try await persistence.removeConfirmed(appID: appA, hostKey: host.publicKey, pairingID: nextConfirmed.pairingID)
                Issue.record("stale delete removed route-updated Keychain trust")
            } catch TetherError.keychain(errSecItemNotFound) {}
            #expect(try await peers.records(appID: appA) == [routed])
            phases.append("real-route-generation-compare-and-swap")
            try await peers.removeConfirmed(routed)
            #expect(try await peers.records(appID: appA).isEmpty)
            phases.append("real-confirmed-generation-compare-and-delete")

            // A second independently generated host exercises deletion/replacement without changing
            // or deleting confirmed trust. Its identity is never stored in the user's Keychain.
            let response = try Bridge.call(["command": "identity.generate"])
            let replacementHost = try TetherIdentity(response: response, appID: appA)
            accounts.append((peerService, appA + "|" + replacementHost.publicKey.base64EncodedString()))
            let first = TetherPeerRecord(appID: appA, hostKey: replacementHost.publicKey, clientKey: a.publicKey,
                                         route: pending.route, confirmed: false)
            try await peers.begin(first)
            try await peers.discardPending(first)
            let replacement = TetherPeerRecord(appID: appA, hostKey: replacementHost.publicKey, clientKey: a.publicKey,
                                               route: pending.route, confirmed: false)
            try await peers.begin(replacement)
            do {
                try await persistence.discardPending(appID: appA, hostKey: replacement.hostKey, pairingID: first.pairingID)
                Issue.record("a stale delete removed a replacement Keychain pairing")
            } catch TetherError.keychain(errSecItemNotFound) {}
            #expect(try await peers.record(appID: appA, hostKey: replacement.hostKey) == replacement)
            try await peers.discardPending(replacement)
            #expect(try await peers.record(appID: appA, hostKey: replacement.hostKey) == nil)
            phases.append("real-replacement-generation-protected-and-pending-discarded")

            // Corrupt only this test's newly created identity; a load must refuse, never rotate it.
            let corrupted = Data([7])
            let changed = SecItemUpdate(query(service: identityService, account: appB) as CFDictionary,
                                        [kSecValueData as String: corrupted] as CFDictionary)
            #expect(changed == errSecSuccess)
            let afterCorruption = TetherIdentityStore(persistence: identityPersistence)
            do { _ = try await afterCorruption.identity(appID: appB); Issue.record("corrupt identity was accepted or rotated") }
            catch TetherError.refused {}
            #expect(try await identityPersistence.load(appID: appB) == corrupted)
            phases.append("real-corrupt-identity-refused-without-reset")
        }
    }
#endif
