import Foundation
import CryptoSwift
import SwCrypt

public typealias Payload = [String: Any]

/// The supported Algorithms
public enum Algorithm: CustomStringConvertible {
  /// No Algorithm, i-e, insecure
  case none

  /// HMAC using SHA-256 hash algorithm
  case hs256(Data)

  /// HMAC using SHA-384 hash algorithm
  case hs384(Data)

  /// HMAC using SHA-512 hash algorithm
  case hs512(Data)

  /// RSA PKCS#1 using SHA-256 hash algorithm
  case rs256(Data)

  /// RSA PKCS#1 using SHA-384 hash algorithm
  case rs384(Data)

  /// RSA PKCS#1 using SHA-512 hash algorithm
  case rs512(Data)
  
  /// RSA PSS using SHA-256 hash algorithm
  case ps256(Data)

  /// RSA PSS using SHA-384 hash algorithm
  case ps384(Data)
  
  /// RSA PSS using SHA-512 hash algorithm
  case ps512(Data)


  public var description: String {
    switch self {
    case .none:
      return "none"
    case .hs256:
      return "HS256"
    case .hs384:
      return "HS384"
    case .hs512:
      return "HS512"
    case .rs256:
      return "RS256"
    case .rs384:
      return "RS384"
    case .rs512:
      return "RS512"
    case .ps256:
      return "PS256"
    case .ps384:
      return "PS384"
    case .ps512:
      return "PS512"
    }
  }

  /// Sign a message using the algorithm
  func sign(_ message: String) -> String {
    func signHS(_ key: Data, variant: CryptoSwift.HMAC.Variant) -> String {
      let messageData = message.data(using: String.Encoding.utf8, allowLossyConversion: false)!
      let mac = HMAC(key: key.bytes, variant: variant)
      let result: [UInt8]
      do {
        result = try mac.authenticate(messageData.bytes)
      } catch {
        result = []
      }
      return base64encode(Data(bytes: result))
    }
    
    func signRS(_ key: Data, variant: CC.DigestAlgorithm, padding: CC.RSA.AsymmetricSAPadding) -> String {
      let messageData = message.data(using: String.Encoding.utf8, allowLossyConversion: false)!
      let result: Data
      do {
          result = try CC.RSA.sign(messageData, derKey: key, padding: padding, digest: variant, saltLen:16)
      } catch {
        result = Data()
      }
      return base64encode(result)
    }

    switch self {
    case .none:
      return ""

    case .hs256(let key):
      return signHS(key, variant: .sha256)

    case .hs384(let key):
      return signHS(key, variant: .sha384)

    case .hs512(let key):
      return signHS(key, variant: .sha512)
  
    case .rs256(let key):
      return signRS(key, variant: .sha256, padding: .pkcs15)
      
    case .rs384(let key):
      return signRS(key, variant: .sha384, padding: .pkcs15)
    
    case .rs512(let key):
      return signRS(key, variant: .sha256, padding: .pkcs15)
      
    case .ps256(let key):
      return signRS(key, variant: .sha256, padding: .pss)
    
    case .ps384(let key):
      return signRS(key, variant: .sha384, padding: .pss)
    
    case .ps512(let key):
      return signRS(key, variant: .sha512, padding: .pss)

    }
  }

  /// Verify a signature for a message using the algorithm
  func verify(_ message: String, signature: Data) -> Bool {
    return sign(message) == base64encode(signature)
  }
}
