import PackageDescription

let package = Package(
  name: "JWT",
  dependencies: [
    .Package(url: "https://github.com/krzyzanowskim/CryptoSwift", versions: Version(0, 6, 1) ..< Version(0, 7, 0)),
  ]
)
