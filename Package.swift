import PackageDescription

let package = Package(
  name: "JWT",
  dependencies: [
    .Package(url: "https://github.com/krzyzanowskim/CryptoSwift", versions: Version(0,2,2)..<Version(0,3,0))
  ]
)
