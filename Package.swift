import PackageDescription

let package = Package(
  name: "JWT",
  dependencies: [
    .Package(url:"https://github.com/krzyzanowskim/CryptoSwift", versions: Version(0,0,1)..<Version(1,0,0))
  ]
)
