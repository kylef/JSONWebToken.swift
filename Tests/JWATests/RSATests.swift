import Foundation
import XCTest
import JWA


@available(OSX 10.12, *)
class RSAPublicKeyAlgorithmTests: XCTestCase {
  let publicKeyData = Data(base64Encoded: "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDdlatRjRjogo3WojgGHFHYLugdUWAY9iR3fy4arWNA1KoS8kVw33cJibXr8bvwUAUparCwlvdbH6dvEOfou0/gCFQsHUfQrSDv+MuSUMAe8jzKE4qW+jK+xQU9a03GUnKHkkle+Q0pX/g6jXZ7r1/xAK5Do2kQ+X5xK9cipRgEKwIDAQAB")!
  let privateKeyData = Data(base64Encoded: "MIICWwIBAAKBgQDdlatRjRjogo3WojgGHFHYLugdUWAY9iR3fy4arWNA1KoS8kVw33cJibXr8bvwUAUparCwlvdbH6dvEOfou0/gCFQsHUfQrSDv+MuSUMAe8jzKE4qW+jK+xQU9a03GUnKHkkle+Q0pX/g6jXZ7r1/xAK5Do2kQ+X5xK9cipRgEKwIDAQABAoGAD+onAtVye4ic7VR7V50DF9bOnwRwNXrARcDhq9LWNRrRGElESYYTQ6EbatXS3MCyjjX2eMhu/aF5YhXBwkppwxg+EOmXeh+MzL7Zh284OuPbkglAaGhV9bb6/5CpuGb1esyPbYW+Ty2PC0GSZfIXkXs76jXAu9TOBvD0ybc2YlkCQQDywg2R/7t3Q2OE2+yo382CLJdrlSLVROWKwb4tb2PjhY4XAwV8d1vy0RenxTB+K5Mu57uVSTHtrMK0GAtFr833AkEA6avx20OHo61Yela/4k5kQDtjEf1N0LfI+BcWZtxsS3jDM3i1Hp0KSu5rsCPb8acJo5RO26gGVrfAsDcIXKC+bQJAZZ2XIpsitLyPpuiMOvBbzPavd4gY6Z8KWrfYzJoI/Q9FuBo6rKwl4BFoToD7WIUS+hpkagwWiz+6zLoX1dbOZwJACmH5fSSjAkLRi54PKJ8TFUeOP15h9sQzydI8zJU+upvDEKZsZc/UhT/SySDOxQ4G/523Y0sz/OZtSWcol/UMgQJALesy++GdvoIDLfJX5GBQpuFgFenRiRDabxrE9MNUZ2aPFaFp+DyAe+b4nDwuJaW2LURbr8AEZga7oQj0uYxcYw==")!
  var publicKey: SecKey {
    let attributes: [String: Any] = [
      kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
      kSecAttrKeySizeInBits as String: 2048,
      kSecAttrKeyClass as String: kSecAttrKeyClassPublic,
    ]

    var error: Unmanaged<CFError>?
    guard let key = SecKeyCreateWithData(publicKeyData as NSData, attributes as NSDictionary, &error) else {
      fatalError("\(error!.takeRetainedValue())")
    }

    return key
  }
  var privateKey: SecKey {
    let attributes: [String: Any] = [
      kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
      kSecAttrKeySizeInBits as String: 2048,
      kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,
    ]

    var error: Unmanaged<CFError>?
    guard let key = SecKeyCreateWithData(privateKeyData as NSData, attributes as NSDictionary, &error) else {
      fatalError("\(error!.takeRetainedValue())")
    }

    return key
  }

  let message = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9".data(using: .utf8)!
  let sha256Signature = Data(base64Encoded: "EkN+DOsnsuRjRO6BxXemmJDm3HbxrbRzXglbN2S4sOkopdU4IsDxTI8jO19W/A4K8ZPJijNLis4EZsHeY559a4DFOd50/OqgHGuERTqYZyuhtF39yxJPAjUESwxk2J5k/4zM3O+vtd1Ghyo4IbqKKSy6J9mTniYJPenn5+HIirE=")!
  let sha384Signature = Data(base64Encoded: "rQ706A2kJ7KjPURXyXK/dZ9Qdm+7ZlaQ1Qt8s43VIX21Wck+p8vuSOKuGltKr9NL")!
  let sha512Signature = Data(base64Encoded: "G7pYfHMO7box9Tq7C2ylieCd5OiU7kVeYUCAc5l1mtqvoGnux8AWR7sXPcsX9V0ir0mhgHG3SMXC7df3qCnGMg==")!

  // MARK: Name

  func testSHA256Name() {
      let algorithm = RSAPublicKey(key: publicKey, hash: .sha256)
      XCTAssertEqual(algorithm.name, "RS256")
  }

  func testSHA384Name() {
      let algorithm = RSAPublicKey(key: publicKey, hash: .sha384)
      XCTAssertEqual(algorithm.name, "RS384")
  }

  func testSHA512Name() {
      let algorithm = RSAPublicKey(key: publicKey, hash: .sha512)
      XCTAssertEqual(algorithm.name, "RS512")
  }

  // MARK: Signing
//
//    func testSHA256Sign() {
//        let algorithm = HMACAlgorithm(key: key, hash: .sha256)
//        XCTAssertEqual(algorithm.sign(message), sha256Signature)
//    }
//
//    func testSHA384Sign() {
//        let algorithm = HMACAlgorithm(key: key, hash: .sha384)
//        XCTAssertEqual(algorithm.sign(message), sha384Signature)
//    }
//
//    func testSHA512Sign() {
//        let algorithm = HMACAlgorithm(key: key, hash: .sha512)
//        XCTAssertEqual(algorithm.sign(message), sha512Signature)
//    }
//
  // MARK: Verify

  func testSHA256Verify() {
      let algorithm = RSAPublicKey(key: publicKey, hash: .sha256)
      XCTAssertTrue(algorithm.verify(message, signature: sha256Signature))

//      let a = RSAPrivateKey(key: privateKey, hash: .sha256)
//      XCTAssertEqual(a.sign(message), sha256Signature)
  }

    func testSHA384Verify() {
        let algorithm = RSAPublicKey(key: publicKey, hash: .sha384)
        XCTAssertTrue(algorithm.verify(message, signature: sha384Signature))
    }

    func testSHA512Verify() {
        let algorithm = RSAPublicKey(key: publicKey, hash: .sha512)
        XCTAssertTrue(algorithm.verify(message, signature: sha512Signature))
    }
}
