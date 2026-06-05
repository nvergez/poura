// swift-tools-version:5.9
import PackageDescription

// macOS CLI for the Oura Ring 4. The application-layer protocol (frame builders, AES
// auth proof, TLV/biosignal decoders) and Keychain live in the shared PouraCore
// package at the repo root — the SAME code the iOS app uses. This target only owns the
// CoreBluetooth driver + CLI arg parsing in main.swift.
let package = Package(
    name: "ble-explorer",
    platforms: [
        .macOS(.v13)
    ],
    dependencies: [
        .package(path: "../PouraCore")
    ],
    targets: [
        .executableTarget(
            name: "ble-explorer",
            dependencies: [
                .product(name: "PouraCore", package: "PouraCore")
            ],
            path: "Sources/ble-explorer"
        )
    ]
)
