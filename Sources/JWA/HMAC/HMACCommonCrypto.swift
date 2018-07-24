import Foundation
import CommonCrypto


extension HMACAlgorithm: SignAlgorithm, VerifyAlgorithm {
  public func sign(_ message: Data) -> Data {
    let context = UnsafeMutablePointer<CCHmacContext>.allocate(capacity: 1)
    defer { context.deallocate() }

    key.withUnsafeBytes() { (buffer: UnsafePointer<UInt8>) in
      CCHmacInit(context, hash.commonCryptoAlgorithm, buffer, size_t(key.count))
    }

    message.withUnsafeBytes { (buffer: UnsafePointer<UInt8>) in
      CCHmacUpdate(context, buffer, size_t(message.count))
    }

    var hmac = Array<UInt8>(repeating: 0, count: Int(hash.commonCryptoDigestLength))
    CCHmacFinal(context, &hmac)

    return Data(hmac)
  }
}


extension HMACAlgorithm.Hash {
  var commonCryptoAlgorithm: CCHmacAlgorithm {
    switch self {
    case .sha256:
      return CCHmacAlgorithm(kCCHmacAlgSHA256)
    case .sha384:
      return CCHmacAlgorithm(kCCHmacAlgSHA384)
    case .sha512:
      return CCHmacAlgorithm(kCCHmacAlgSHA512)
    }
  }

  var commonCryptoDigestLength: Int32 {
    switch self {
    case .sha256:
      return CC_SHA256_DIGEST_LENGTH
    case .sha384:
      return CC_SHA384_DIGEST_LENGTH
    case .sha512:
      return CC_SHA512_DIGEST_LENGTH
    }
  }
}
