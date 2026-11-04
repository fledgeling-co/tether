import AppKit

/// An owned application host gives the SDK its normal signed Keychain identity during XCTest.
@main
struct ValidationApp {
    @MainActor static func main() {
        let application = NSApplication.shared
        application.setActivationPolicy(.prohibited)
        application.run()
    }
}
