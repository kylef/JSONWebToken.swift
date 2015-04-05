import Foundation
import CryptoSwift

public typealias Payload = [String:AnyObject]

/// The supported Algorithms
public enum Algorithm : Printable {
  /// No Algorithm, i-e, insecure
  case None

  /// HMAC using SHA-256 hash algorithm
  case HS256(String)

  static func algorithm(name:String, key:String?) -> Algorithm? {
    if name == "none" {
      if let key = key {
        return nil  // We don't allow nil when we configured a key
      }
      return Algorithm.None
    } else if let key = key {
      if name == "HS256" {
        return .HS256(key)
      }
    }

    return nil
  }

  public var description:String {
    switch self {
    case .None:
      return "none"
    case .HS256(let key):
      return "HS256"
    }
  }

  /// Sign a message using the algorithm
  func sign(message:String) -> String {
    switch self {
    case .None:
      return ""

    case .HS256(let key):
      let mac = Authenticator.HMAC(key: key.dataUsingEncoding(NSUTF8StringEncoding, allowLossyConversion: false)!, variant:.sha256)
      let result = mac.authenticate(message.dataUsingEncoding(NSUTF8StringEncoding, allowLossyConversion: false)!)!
      return base64encode(result)
    }
  }

  /// Verify a signature for a message using the algorithm
  func verify(message:String, signature:NSData) -> Bool {
    return sign(message) == base64encode(signature)
  }
}

// MARK: Encoding

/*** Encode a payload
  :param: payload The payload to sign
  :param: algorithm The algorithm to sign the payload with
  :returns: The JSON web token as a String
*/
public func encode(payload:Payload, algorithm:Algorithm) -> String {
  func encodeJSON(payload:Payload) -> String? {
    if let data = NSJSONSerialization.dataWithJSONObject(payload, options: NSJSONWritingOptions(0), error: nil) {
      return base64encode(data)
    }

    return nil
  }

  let header = encodeJSON(["typ": "JWT", "alg": algorithm.description])!
  let payload = encodeJSON(payload)!
  let signingInput = "\(header).\(payload)"
  let signature = algorithm.sign(signingInput)
  return "\(signingInput).\(signature)"
}
