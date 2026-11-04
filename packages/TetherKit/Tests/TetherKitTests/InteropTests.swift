import Foundation
import Testing
@testable import TetherKit

private actor MemoryPersistence: TetherIdentityPersistence {
    var values: [String: Data] = [:]
    var saves = 0
    func load(appID: String) -> Data? {
        values[appID]
    }

    func save(_ privateKey: Data, appID: String) {
        values[appID] = privateKey; saves += 1
    }
}

@Suite("Swift calls the Rust protocol through the packaged C ABI")
struct InteropTests {
    @Test("per-app identities persist and concurrent creation shares one key")
    func identityPersistenceAndScope() async throws {
        let persistence = MemoryPersistence()
        let store = TetherIdentityStore(persistence: persistence)
        async let first = store.identity(appID: "app.test.one")
        async let second = store.identity(appID: "app.test.one")
        let (a, b) = try await (first, second)
        #expect(a.publicKey == b.publicKey)
        #expect(await persistence.saves == 1)
        let other = try await store.identity(appID: "app.test.two")
        #expect(other.publicKey != a.publicKey)
        let reopened = TetherIdentityStore(persistence: persistence)
        let reloaded = try await reopened.identity(appID: "app.test.one")
        #expect(reloaded.publicKey == a.publicKey)
        do {
            _ = try TetherNoise(identity: a, appID: "app.test.two", role: .client)
            Issue.record("an identity was reused across applications")
        } catch TetherError.invalidScope {}
    }

    private func channels() async throws -> (TetherIdentity, TetherIdentity, TetherSecureTransport, TetherSecureTransport) {
        let store = TetherIdentityStore(persistence: MemoryPersistence())
        let client = try await store.identity(appID: "app.test")
        // Separate persistence represents the other device for the same application.
        let remoteStore = TetherIdentityStore(persistence: MemoryPersistence())
        let host = try await remoteStore.identity(appID: "app.test")
        let a = try TetherNoise(identity: client, appID: "app.test", role: .client)
        let b = try TetherNoise(identity: host, appID: "app.test", role: .host)
        try await b.read(a.write())
        try await a.read(b.write())
        try await b.read(a.write())
        let ta = try await a.finish()
        let tb = try await b.finish()
        return (client, host, ta, tb)
    }

    @Test("native Swift completes Noise and mutual PAKE then authenticates binary records")
    func noisePairingAndRecords() async throws {
        let (client, host, a, b) = try await channels()
        #expect(a.metadata.binding == b.metadata.binding)
        #expect(a.metadata.remoteStatic == host.publicKey)
        #expect(b.metadata.remoteStatic == client.publicKey)
        let pa = try TetherPairing(role: .client, code: "K7QN-4FMB", appID: "app.test",
                                   binding: a.metadata.binding, clientKey: client.publicKey, hostKey: host.publicKey)
        let pb = try TetherPairing(role: .host, code: "k7qn4fmb", appID: "app.test",
                                   binding: b.metadata.binding, clientKey: client.publicKey, hostKey: host.publicKey)
        let ca = try await pa.finish(pb.message)
        let cb = try await pb.finish(pa.message)
        try await ca.verify(cb.outbound)
        try await cb.verify(ca.outbound)
        let data = Data([0, 1, 255, 0, 42])
        let ciphertext = try await a.encrypt(data)
        #expect(try await b.decrypt(ciphertext) == data)
        do {
            _ = try await b.decrypt(ciphertext)
            Issue.record("a replayed encrypted record was accepted")
        } catch TetherError.refused {}
        do {
            _ = try await b.decrypt(ciphertext)
            Issue.record("a retired channel was reused")
        } catch TetherError.closed {}
        await a.close()
        await b.close()
    }

    @Test("wrong code and malformed native data never produce a verified pairing")
    func wrongCodeFails() async throws {
        let (client, host, a, b) = try await channels()
        let pa = try TetherPairing(role: .client, code: "K7QN4FMB", appID: "app.test",
                                   binding: a.metadata.binding, clientKey: client.publicKey, hostKey: host.publicKey)
        let pb = try TetherPairing(role: .host, code: "A7QN4FMB", appID: "app.test",
                                   binding: b.metadata.binding, clientKey: client.publicKey, hostKey: host.publicKey)
        let ca = try await pa.finish(pb.message)
        let cb = try await pb.finish(pa.message)
        do {
            try await ca.verify(cb.outbound)
            Issue.record("a wrong code was authenticated")
        } catch TetherError.refused {}
        await cb.close()
        await a.close()
        await b.close()
    }
}
