// swift-tools-version: 5.10
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "SwiftPasskeyKit",
    platforms: [
        .macOS(.v14),
        .iOS(.v17),
    ],
    products: [
        // Products define the executables and libraries a package produces, making them visible to other packages.
        .library(
            name: "SwiftPasskeyKit",
            targets: ["SwiftPasskeyKit"]),
    ],
    dependencies: [
        // Dependencies declare other packages that this package depends on.
        .package(url: "https://github.com/Soneso/stellar-ios-mac-sdk", .upToNextMajor(from: "3.2.0")),
        //.package(path: "/Users/chris/Soneso/github/stellar-ios-mac-sdk") // local, if it is not updateing, you can use fix_spm_cache.sh
    ],
    targets: [
        // Targets are the basic building blocks of a package, defining a module or a test suite.
        // Targets can depend on other targets in this package and products from dependencies.
        .target(
            name: "SwiftPasskeyKit",
            dependencies: [
                // Dependencies declare other packages that this package depends on.
                .product(name:"stellarsdk", package:"stellar-ios-mac-sdk"),
            ]),
        .testTarget(
            name: "SwiftPasskeyKitTests",
            dependencies: ["SwiftPasskeyKit"]),
    ]
)
