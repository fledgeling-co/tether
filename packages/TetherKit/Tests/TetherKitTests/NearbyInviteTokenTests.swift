import Foundation
import Network
import Testing
@testable import TetherKit

/// The one-time invite token, from the Swift kit's side of it.
///
/// An invite used to be a line anybody on the local network could compose, and the `invited` badge
/// was set by the name a peer announced. Both now turn on a 32-byte token the *device* mints for
/// one connection: the device writes it as its first line, an invite is read only when it echoes
/// that token, and the device repeats it in `pair.nearby` so the host can tell which request
/// answered its own invite.
@Suite("Nearby invite tokens")
struct NearbyInviteTokenTests {
    private func mint() throws -> String {
        try #require(try Bridge.call(["command": "discovery.invite_token"])["token"] as? String)
    }

    @Test func aTokenIsThirtyTwoBytesOfBase64urlAndNeverRepeats() throws {
        let first = try mint(), second = try mint()
        #expect(first.count == 43)
        #expect(first.allSatisfy { $0.isLetter || $0.isNumber || $0 == "-" || $0 == "_" })
        #expect(first != second)
    }

    @Test func anInviteIsReadOnlyWhenItEchoesTheTokenThisDeviceIssued() throws {
        let issued = try mint()
        let challenge = try #require(try Bridge.call(["command": "discovery.challenge", "app": "test.app", "token": issued])["line"] as? String)
        // The inviting side reads the token off the challenge rather than inventing one.
        let read = try #require(try Bridge.call(["command": "discovery.read_challenge", "app": "test.app", "line": challenge])["token"] as? String)
        #expect(read == issued)
        let foreignApp = try Bridge.call(["command": "discovery.read_challenge", "app": "other.app", "line": challenge])["token"] as? String
        #expect(foreignApp == nil)

        let honest = try #require(try Bridge.call(["command": "discovery.invite", "app": "test.app", "name": "Studio Mac",
                                               "port": 15912, "token": issued])["line"] as? String)
        let accepted = try #require(try Bridge.call(["command": "discovery.read_invite", "app": "test.app", "line": honest,
                                                 "remote": "192.168.1.5", "token": issued])["invite"] as? [String: Any])
        #expect(accepted["port"] as? Int == 15912)
        #expect(accepted["token"] as? String == issued)

        // The defect: a line anybody could compose, with no token on it at all.
        let forged = #"{"v":1,"app":"test.app","port":15912,"name":"Studio Mac"}"#
        let untokened = try Bridge.call(["command": "discovery.read_invite", "app": "test.app", "line": forged,
                                         "remote": "192.168.1.5", "token": issued])["invite"] as? [String: Any]
        #expect(untokened == nil)
        // Somebody else's live token is refused too, so the token has to be this connection's.
        let foreign = try mint()
        let elsewhere = try #require(try Bridge.call(["command": "discovery.invite", "app": "test.app", "name": "Studio Mac",
                                                  "port": 15912, "token": foreign])["line"] as? String)
        let somebodyElses = try Bridge.call(["command": "discovery.read_invite", "app": "test.app", "line": elsewhere,
                                             "remote": "192.168.1.5", "token": issued])["invite"] as? [String: Any]
        #expect(somebodyElses == nil)
    }

    /// The inviting half over a real socket. A peer that writes no challenge — an older device,
    /// or anything else holding that port — must cost this host a deadline and no invite. Before
    /// the exchange released itself on the deadline this ran past 60 seconds instead of failing.
    @Test(.timeLimit(.minutes(1)))
    func anInviterFacingAPeerThatWritesNoChallengeFailsAndSendsNothing() async throws {
        let received = Received()
        let listener = try NWListener(using: .tcp)
        listener.newConnectionHandler = { connection in
            // Accept, say nothing, and record anything the host writes unprompted.
            connection.start(queue: .global())
            connection.receive(minimumIncompleteLength: 1, maximumLength: 512) { data, _, _, _ in
                if let data, !data.isEmpty { received.set(String(data: data, encoding: .utf8) ?? "<bytes>") }
            }
        }
        listener.start(queue: .global())
        defer { listener.cancel() }
        var port: UInt16?
        for _ in 0 ..< 200 where port == nil {
            port = listener.port?.rawValue
            if port == nil { try await Task.sleep(for: .milliseconds(25)) }
        }
        let bound = try #require(port)
        let peer = TetherNearbyPeer(id: "device", name: "Field iPhone", kind: "iPhone", hostKey: nil,
                                    addresses: ["127.0.0.1"], port: bound,
                                    endpoint: .hostPort(host: "127.0.0.1", port: NWEndpoint.Port(rawValue: bound)!))
        let started = Date()
        await #expect(throws: (any Error).self) {
            try await TetherNearbyInviteListener.invite(peer, appID: "test.app", hostName: "Studio Mac", port: 7445)
        }
        #expect(Date().timeIntervalSince(started) < 30, "the exchange released itself rather than parking")
        #expect(received.get() == nil, "no invite goes out before a token has been read")
    }

    private final class Received: @unchecked Sendable {
        private let lock = NSLock()
        private var value: String?
        func set(_ text: String?) { lock.withLock { value = text } }
        func get() -> String? { lock.withLock { value } }
    }
}
