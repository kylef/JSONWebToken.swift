import PackageDescription


#if os(macOS) || os(iOS) || os(watchOS) || os(tvOS)
let package = Package(
  name: "JWT",
  dependencies: [
    .Package(url: "https://github.com/kylef-archive/CommonCrypto.git", majorVersion: 1),
  ],
  exclude: [
    "Sources/JWT/HMACCryptoSwift.swift",
  ]
)
#else
let package = Package(
  name: "JWT",
  dependencies: [
    .Package(url: "https://github.com/krzyzanowskim/CryptoSwift.git", majorVersion: 0, minor: 6),
  ],
  exclude: [
    "Sources/JWT/HMACCommonCrypto.swift",
  ]
)
#endif
