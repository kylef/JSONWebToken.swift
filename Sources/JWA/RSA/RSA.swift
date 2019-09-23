#if os(macOS)

import Foundation
import CommonCrypto
import Security

@available(OSX 10.12, *)
public enum RSAHash {
  case sha256
  case sha384
  case sha512

  var algorithm: SecKeyAlgorithm {
    switch self {
    case .sha256:
      return SecKeyAlgorithm.rsaSignatureDigestPKCS1v15SHA256
    case .sha384:
      return SecKeyAlgorithm.rsaSignatureDigestPKCS1v15SHA384
    case .sha512:
      return SecKeyAlgorithm.rsaSignatureDigestPKCS1v15SHA512
    }
  }
}


@available(OSX 10.12, *)
final public class RSAPublicKey: Algorithm, VerifyAlgorithm {
  let hash: RSAHash
  let key: SecKey

  public init(key: SecKey, hash: RSAHash) {
    self.hash = hash
    self.key = key
  }

  public var name: String {
    switch hash {
    case .sha256:
      return "RS256"
    case .sha384:
      return "RS384"
    case .sha512:
      return "RS512"
    }
  }

  public func verify(_ message: Data, signature: Data) -> Bool {
    var error: Unmanaged<CFError>?
    let result = SecKeyVerifySignature(key, hash.algorithm, message as NSData, signature as NSData, &error)
    print(error)
    return result
  }
}


//@available(OSX 10.12, *)
//final public class RSAPrivateKey: Algorithm {//, SignAlgorithm {
//  let hash: RSAHash
//  let key: SecKey
//
//  public init(key: SecKey, hash: RSAHash) {
//    // TODO is sec key
//    self.hash = hash
//    self.key = key
//  }
//
//  public var name: String {
//    switch hash {
//    case .sha256:
//      return "RS256"
//    case .sha384:
//      return "RS384"
//    case .sha512:
//      return "RS512"
//    }
//  }
//
//  public func verify(_ message: Data, signature: Data) -> Bool {
//    let alg = SecKeyAlgorithm.rsaSignatureDigestPKCS1v15SHA256
//    return SecKeyVerifySignature(key, alg, message as NSData, signature as NSData, nil)
//  }
//
//  public func sign(_ message: Data) -> Data {
//    let alg = SecKeyAlgorithm.rsaSignatureDigestPKCS1v15SHA256
//
//    var error: Unmanaged<CFError>?
//    guard let x = SecKeyCreateSignature(key, alg, message as NSData, &error) else {
//      fatalError("\(error?.takeRetainedValue())")
//    }
//
//    return x as NSData as Data
////    sign(<#T##message: Data##Data#>)
//  }
//}

#endif
