// swift-tools-version: 6.0
import Foundation
import PackageDescription

let localBridge = "packages/TetherKit/Artifacts/TetherFFI.xcframework"
let root = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
let bridge: Target = FileManager.default.fileExists(atPath: root.appendingPathComponent(localBridge).path)
    ? .binaryTarget(name: "TetherFFI", path: localBridge)
    : .binaryTarget(
        name: "TetherFFI",
        url: "https://github.com/fledgeling-co/tether/releases/download/v0.1.0-preview.4/TetherFFI.xcframework.zip",
        checksum: "456e6629a107ded761417cf40fc0ba4ff80c140cdd4fd0e2795dbf2cfcdb77bf")

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
