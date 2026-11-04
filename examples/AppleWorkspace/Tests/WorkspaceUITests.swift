import XCTest

@MainActor final class WorkspaceUITests: XCTestCase {
    private var app: XCUIApplication!
    override func setUp() {
        continueAfterFailure = false
        app = XCUIApplication()
        app.launchArguments = ["--design-fixtures"]
        app.launch()
    }
    override func tearDown() { app.terminate(); app = nil }
    private func press(_ element: XCUIElement) {
        XCTAssertTrue(element.waitForExistence(timeout: 8))
        #if os(macOS)
        element.click()
        #else
        element.tap()
        #endif
    }
    func testMultipleSavedHostsStayIndependentAndOffline() {
        #if os(iOS)
        let hosts = app.buttons["tether.show-hosts"].firstMatch
        if hosts.waitForExistence(timeout: 3) { hosts.tap() }
        #endif
        // Native list rows merge their labels and can omit the link's identifier.
        let name = "host-2.local:9000"
        press(app.descendants(matching: .any).matching(NSPredicate(format: "label BEGINSWITH %@", name)).firstMatch)
        XCTAssertTrue(app.staticTexts[name].firstMatch.waitForExistence(timeout: 5))
        XCTAssertTrue(app.staticTexts.matching(NSPredicate(format: "label BEGINSWITH %@", "Connection status: Offline")).firstMatch.exists)
        XCTAssertTrue(app.staticTexts["Design fixtures · No network connection"].exists)
        let attachment = XCTAttachment(screenshot: app.screenshot())
        attachment.name = "Native host selection · synthetic offline records"
        attachment.lifetime = .keepAlways; add(attachment)
    }
    func testManualPairingFailureIsVisibleAndKeepsFormOpen() {
        press(app.buttons.matching(identifier: "tether.pair").firstMatch)
        let address = app.textFields["tether.pair.address"]
        press(address); address.typeText("unavailable.local")
        let code = app.secureTextFields["tether.pair.code"]
        press(code); code.typeText("ABCD2345")
        press(app.buttons["tether.pair.submit"])
        XCTAssertTrue(app.descendants(matching: .any).matching(identifier: "tether.pair.error").firstMatch.waitForExistence(timeout: 5))
        #if os(iOS)
        // SwiftUI Form exposes a CollectionView on iOS, with lazy off-screen fields.
        app.collectionViews.containing(.button, identifier: "tether.pair.submit").firstMatch.swipeDown()
        #endif
        XCTAssertTrue(address.waitForExistence(timeout: 3))
        let attachment = XCTAttachment(screenshot: app.screenshot())
        attachment.name = "Native pairing error · synthetic client refuses network"
        attachment.lifetime = .keepAlways; add(attachment)
    }
}
