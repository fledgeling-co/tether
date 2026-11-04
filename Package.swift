// swift-tools-version: 6.0
import Foundation
import PackageDescription

let localBridge = "packages/TetherKit/Artifacts/TetherFFI.xcframework"
let root = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
let bridge: Target = FileManager.default.fileExists(atPath: root.appendingPathComponent(localBridge).path)
    ? .binaryTarget(name: "TetherFFI", path: localBridge)
    : .binaryTarget(
        name: "TetherFFI",
        url: "https://github.com/fledgeling-co/tether/releases/download/v0.1.0-preview.1/TetherFFI.xcframework.zip",
        checksum: "bf93d1d7a24cd823a86a48e6d92684912195d218030ce37d70477206ce1e9d75")

let package = Package(
    name: "Tether",
    platforms: [.macOS(.v15), .iOS(.v18)],
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
