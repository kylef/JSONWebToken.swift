// swift-tools-version:4.0

import PackageDescription


#if os(macOS) || os(iOS) || os(watchOS) || os(tvOS)
#if canImport(CommonCrypto)
let dependencies: [Package.Dependency] = []
#else
let dependencies = [
  Package.Dependency.package(url: "https://github.com/kylef-archive/CommonCrypto.git", from: "1.0.0"),
]
#endif
let excludes = ["HMAC/HMACCryptoSwift.swift"]
let targetDependencies: [Target.Dependency] = []
#else
let dependencies = [
  Package.Dependency.package(url: "https://github.com/krzyzanowskim/CryptoSwift.git", from: "0.10.0"),
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
    .target(name: "JWA", dependencies: targetDependencies, exclude: excludes),
    .target(name: "JWT", dependencies: ["JWA"]),
    .testTarget(name: "JWATests", dependencies: ["JWA"]),
    .testTarget(name: "JWTTests", dependencies: ["JWT"]),
  ]
)
