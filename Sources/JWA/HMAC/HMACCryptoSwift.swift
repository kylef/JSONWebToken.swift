import Foundation
import CryptoSwift


extension HMACAlgorithm: SignAlgorithm, VerifyAlgorithm {
  public func sign(_ message: Data) -> Data {
    let mac = HMAC(key: key.bytes, variant: hash.cryptoSwiftVariant)

    let result: [UInt8]
    do {
      result = try mac.authenticate(message.bytes)
    } catch {
      result = []
    }

    return Data(bytes: result)
  }
}


extension HMACAlgorithm.Hash {
  var cryptoSwiftVariant: HMAC.Variant {
    switch self {
    case .sha256:
      return .sha256
    case .sha384:
      return .sha384
    case .sha512:
      return .sha512
    }
  }
}
