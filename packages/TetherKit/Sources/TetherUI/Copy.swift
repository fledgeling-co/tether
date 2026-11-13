import TetherKit

/// Fixed copy from the Rust core, looked up once per device name.
@MainActor enum UICopy {
    private static var cache: [String: [String: String]] = [:]
    static func text(_ key: String, device: String = "device") -> String {
        if cache[device] == nil { cache[device] = TetherCopy.strings(device: device) }
        return cache[device]?[key] ?? key
    }
}
