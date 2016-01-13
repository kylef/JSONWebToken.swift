import PackageDescription

let package = Package(
  name: "JWT",
  dependencies: [
    .Package(url:"https://github.com/krzyzanowskim/CryptoSwift", majorVersion: 0, minor: 1)
  ]
)
