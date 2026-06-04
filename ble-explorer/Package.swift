// swift-tools-version:5.9
import PackageDescription

let package = Package(
    name: "ble-explorer",
    platforms: [
        .macOS(.v13)
    ],
    targets: [
        .executableTarget(
            name: "ble-explorer",
            path: "Sources/ble-explorer"
        )
    ]
)
