import PackageDescription


#if os(macOS) || os(iOS) || os(watchOS) || os(tvOS)
let package = Package(
  name: "JWT",
  dependencies: [
    .Package(url: "https://github.com/kylef-archive/CommonCrypto.git", majorVersion: 1),
  ],
  exclude: [
    "Sources/HMACCryptoSwift.swift",
  ]
)
#else
let package = Package(
  name: "JWT",
  dependencies: [
    .Package(url: "https://github.com/krzyzanowskim/CryptoSwift.git", majorVersion: 0, minor: 6),
  ],
  exclude: [
    "Sources/HMACCommonCrypto.swift",
  ]
)
#endif
