import PackageDescription



let package = Package(
  name: "JWT",
  dependencies: [
    .Package(url: "https://github.com/krzyzanowskim/CryptoSwift.git", majorVersion: 0, minor: 8),
  ],
  exclude: [
    "Sources/JWT/HMACCommonCrypto.swift",
  ]
)

