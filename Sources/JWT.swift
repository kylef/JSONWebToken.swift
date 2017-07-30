import Foundation
import CryptoSwift
import SwiftyRSA

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
  
  /// RSA using SHA-256 hash algorithm
  case rs256(Data)
  
  // RSA using SHA-512 hash algorithm
  case rs512(Data)
  
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
    case .rs512:
      return "RS512"
    }
  }
  
  /// Sign a message using the algorithm
  func sign(_ message: String) throws -> String {
    
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
    
    func signRS(_ key: Data, digestType: Signature.DigestType) throws -> String {
      
      let privateKey = try PrivateKey(data: key)
      
      let clear = try ClearMessage(string: message, using: .utf8)
      
      let signature = try clear.signed(with: privateKey, digestType: digestType)
      let base64Signature = signature.base64String
      
      return base64Signature
      
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
      return try signRS(key, digestType: .sha256)
      
    case .rs512(let key):
      return try signRS(key, digestType: .sha512)
      
    }
  }
  
  /// Verify a signature for a message using the algorithm
  func verify(_ message: String, signature: Data) throws -> Bool {
    return try sign(message) == base64encode(signature)
  }
}
