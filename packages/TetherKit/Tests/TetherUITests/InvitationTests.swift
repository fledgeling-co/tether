import Foundation
import XCTest
@testable import TetherUI
import TetherKit

final class InvitationTests: XCTestCase {
    private let now = Date(timeIntervalSince1970: 1_800_000_000)
    func testInvitationRetainsExplicitRouteAndAppScope() throws {
        for route in [TetherRoute.privateNetwork(host: "studio.local", port: 9000),
                      .cloud(relayURL: URL(string: "wss://relay.example/tether")!, hostID: String(repeating: "a", count: 52))] {
            let value = try TetherPairingInvitation(appID: "app.example.demo", route: route, code: "ABCD2345", expiresAt: now.addingTimeInterval(300), now: now)
            let url = try value.url(now: now)
            XCTAssertEqual(try TetherPairingInvitation.decode(url, expectedAppID: value.appID, now: now), value)
            XCTAssertThrowsError(try TetherPairingInvitation.decode(url, expectedAppID: "other.app", now: now))
            XCTAssertThrowsError(try TetherPairingInvitation.decode(url, expectedAppID: value.appID, now: now.addingTimeInterval(301)))
        }
    }
    func testInvitationsCannotExtendPairingWindowOrCarryUnboundedInput() throws {
        XCTAssertThrowsError(try TetherPairingInvitation(appID: "app.demo", route: .privateNetwork(host: "mac.local", port: 1), code: "ABCD2345", expiresAt: now.addingTimeInterval(600), now: now))
        XCTAssertThrowsError(try TetherPairingInvitation.decode(URL(string: "tether://pair?data=" + String(repeating: "a", count: 5000))!, expectedAppID: "app.demo", now: now))
        XCTAssertThrowsError(try TetherPairingInvitation.decode(URL(string: "tether://pair?data=e30&data=e30")!, expectedAppID: "app.demo", now: now))
    }
    func testRoutesRejectInsecureRelayCredentialsAndWildcardInvitation() throws {
        for relay in ["ws://relay.example", "wss://user:secret@relay.example", "wss://relay.example?token=x", "wss://relay.example#x"] {
            XCTAssertThrowsError(try TetherPairingFields.cloudRoute(relay: relay, hostID: String(repeating: "a", count: 52)))
        }
        for address in ["0.0.0.0", "::", "[::]", "https://mac.local", "mac.local/path", "mac local"] {
            XCTAssertThrowsError(try TetherPairingFields.privateRoute(address: address, port: "9000"))
        }
        XCTAssertThrowsError(try TetherPairingFields.privateRoute(address: "mac.local", port: "0"))
        XCTAssertThrowsError(try TetherPairingFields.cloudRoute(relay: "wss://relay.example", hostID: "wrong"))
    }
    func testCanonicalCodeAlphabet() throws {
        for code in ["ABCDEFGH", "01234567", "VWXYZ234"] {
            XCTAssertNoThrow(try TetherPairingInvitation(appID: "app.demo", route: .privateNetwork(host: "mac.local", port: 9000), code: code, expiresAt: now.addingTimeInterval(30), now: now))
        }
        for code in ["IIIIIIII", "OOOOOOOO", "ABCD234", "abcdefgh"] {
            XCTAssertThrowsError(try TetherPairingInvitation(appID: "app.demo", route: .privateNetwork(host: "mac.local", port: 9000), code: code, expiresAt: now.addingTimeInterval(30), now: now))
        }
    }
}
