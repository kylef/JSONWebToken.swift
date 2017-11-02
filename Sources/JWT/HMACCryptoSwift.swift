import Foundation
import CryptoSwift


extension HMACAlgorithm {
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


func hmac(algorithm: HMACAlgorithm, key: Data, message: Data) -> Data {
  let mac = HMAC(key: key.bytes, variant: algorithm.cryptoSwiftVariant)
  let result: [UInt8]
  do {
    result = try mac.authenticate(message.bytes)
  } catch {
    result = []
  }
  return Data(bytes: result)
}
