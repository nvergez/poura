// swift-tools-version:5.9
import PackageDescription

// PouraCore — the platform-agnostic Oura Ring 4 protocol core.
//
// SINGLE SOURCE OF TRUTH for the application-layer protocol (frame builders, AES auth
// proof, TLV/biosignal decoders) + Keychain. Contains NO CoreBluetooth and NO UI, so
// it builds for macOS, iOS, and as a test target.
//
// Consumed by BOTH apps in this repo as a sibling SPM dependency (`path: ../PouraCore`):
//   • ble-explorer/  — the macOS CLI
//   • ios-app/       — the SwiftUI iOS app
// There is exactly one copy of the protocol logic; fixes apply to both apps at once.
let package = Package(
    name: "PouraCore",
    platforms: [
        .iOS(.v16),
        .macOS(.v13)
    ],
    products: [
        .library(name: "PouraCore", targets: ["PouraCore"])
    ],
    targets: [
        .target(name: "PouraCore"),
        .testTarget(name: "PouraCoreTests", dependencies: ["PouraCore"])
    ]
)
