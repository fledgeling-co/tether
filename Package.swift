// swift-tools-version: 6.0
import Foundation
import PackageDescription

let localBridge = "packages/TetherKit/Artifacts/TetherFFI.xcframework"
let root = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
let bridge: Target = FileManager.default.fileExists(atPath: root.appendingPathComponent(localBridge).path)
    ? .binaryTarget(name: "TetherFFI", path: localBridge)
    : .binaryTarget(
        name: "TetherFFI",
        url: "https://github.com/fledgeling-co/tether/releases/download/v0.1.0-preview.5/TetherFFI.xcframework.zip",
        checksum: "a0aa4d5d768dc91d5158a755cbf7ed83b8e24aaee7ee887a9c93e580eff05402")

let package = Package(
    name: "Tether",
    platforms: [.macOS(.v14), .iOS(.v17)],
    products: [
        .library(name: "TetherKit", targets: ["TetherKit"]),
        .library(name: "TetherUI", targets: ["TetherUI"]),
        .library(name: "TetherDuoUI", targets: ["TetherDuoUI"])
    ],
    targets: [
        bridge,
        .target(name: "TetherKit", dependencies: ["TetherFFI"], path: "packages/TetherKit/Sources/TetherKit"),
        .target(name: "TetherUI", dependencies: ["TetherKit"], path: "packages/TetherKit/Sources/TetherUI"),
        .target(name: "TetherDuoUI", dependencies: ["TetherUI"], path: "packages/TetherKit/Sources/TetherDuoUI"),
        .testTarget(name: "TetherKitTests", dependencies: ["TetherKit"], path: "packages/TetherKit/Tests/TetherKitTests"),
        .testTarget(name: "TetherUITests", dependencies: ["TetherUI"], path: "packages/TetherKit/Tests/TetherUITests")
    ]
)
