// swift-tools-version:5.1

import PackageDescription


#if os(macOS) || os(iOS) || os(watchOS) || os(tvOS)
let dependencies: [Package.Dependency] = []
let excludes = ["HMAC/HMACCryptoSwift.swift"]
let targetDependencies: [Target.Dependency] = []
#else
let dependencies = [
  Package.Dependency.package(url: "https://github.com/krzyzanowskim/CryptoSwift.git", from: "0.8.0"),
]
let excludes = ["HMAC/HMACCommonCrypto.swift"]
let targetDependencies: [Target.Dependency] = ["CryptoSwift"]
#endif


let package = Package(
  name: "JWT",
  products: [
    .library(name: "JWT", targets: ["JWT"]),
  ],
  dependencies: dependencies,
  targets: [
    .target(name: "JWA",
      exclude: excludes,
      linkerSettings: [
        .linkedFramework("CommonCrypto", .when(platforms: [.iOS, .macOS, .watchOS, .tvOS])),
      ]),
    .target(name: "JWT", dependencies: ["JWA"]),
    .testTarget(name: "JWATests", dependencies: ["JWA"]),
    .testTarget(name: "JWTTests", dependencies: ["JWT"]),
  ]
)
