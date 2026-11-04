// swift-tools-version: 6.0
import PackageDescription
let package = Package(
    name: "TetherKit",
    platforms: [.macOS(.v15), .iOS(.v18)],
    products: [.library(name: "TetherKit", targets: ["TetherKit"]),
               .library(name: "TetherUI", targets: ["TetherUI"]),
               .library(name: "TetherDuoUI", targets: ["TetherDuoUI"])],
    targets: [
        .binaryTarget(name: "TetherFFI", path: "Artifacts/TetherFFI.xcframework"),
        .target(name: "TetherKit", dependencies: ["TetherFFI"]),
        .target(name: "TetherUI", dependencies: ["TetherKit"]),
        .target(name: "TetherDuoUI", dependencies: ["TetherUI"]),
        .testTarget(name: "TetherKitTests", dependencies: ["TetherKit"]),
        .testTarget(name: "TetherUITests", dependencies: ["TetherUI"])
    ]
)
