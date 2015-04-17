import Foundation
import CryptoSwift

public typealias Payload = [String:AnyObject]

/// The supported Algorithms
public enum Algorithm : Printable {
  /// No Algorithm, i-e, insecure
  case None

  /// HMAC using SHA-256 hash algorithm
  case HS256(String)

  /// HMAC using SHA-384 hash algorithm
  case HS384(String)

  /// HMAC using SHA-512 hash algorithm
  case HS512(String)

  static func algorithm(name:String, key:String?) -> Algorithm? {
    if name == "none" {
      if let key = key {
        return nil  // We don't allow nil when we configured a key
      }
      return Algorithm.None
    } else if let key = key {
      if name == "HS256" {
        return .HS256(key)
      } else if name == "HS384" {
        return .HS384(key)
      } else if name == "HS512" {
        return .HS512(key)
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
    case .HS384(let key):
      return "HS384"
    case .HS512(let key):
      return "HS512"
    }
  }

  /// Sign a message using the algorithm
  func sign(message:String) -> String {
    func signHS(key:String, variant:CryptoSwift.HMAC.Variant) -> String {
      let keyData = key.dataUsingEncoding(NSUTF8StringEncoding, allowLossyConversion: false)!
      let messageData = message.dataUsingEncoding(NSUTF8StringEncoding, allowLossyConversion: false)!
      let mac = Authenticator.HMAC(key: keyData.arrayOfBytes(), variant:variant)
      let result = mac.authenticate(messageData.arrayOfBytes())!
      return base64encode(NSData.withBytes(result))
    }

    switch self {
    case .None:
      return ""

    case .HS256(let key):
      return signHS(key, .sha256)

    case .HS384(let key):
      return signHS(key, .sha384)

    case .HS512(let key):
      return signHS(key, .sha512)
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

public class PayloadBuilder {
  var payload = Payload()

  public var issuer:String? {
    get {
      return payload["iss"] as? String
    }
    set {
      payload["iss"] = newValue
    }
  }

  public var audience:String? {
    get {
      return payload["aud"] as? String
    }
    set {
      payload["aud"] = newValue
    }
  }

  public var expiration:NSDate? {
    get {
      if let expiration = payload["exp"] as? NSTimeInterval {
        return NSDate(timeIntervalSince1970: expiration)
      }

      return nil
    }
    set {
      payload["exp"] = newValue?.timeIntervalSince1970
    }
  }

  public var notBefore:NSDate? {
    get {
      if let notBefore = payload["nbf"] as? NSTimeInterval {
        return NSDate(timeIntervalSince1970: notBefore)
      }

      return nil
    }
    set {
      payload["nbf"] = newValue?.timeIntervalSince1970
    }
  }

  public var issuedAt:NSDate? {
    get {
      if let issuedAt = payload["iat"] as? NSTimeInterval {
        return NSDate(timeIntervalSince1970: issuedAt)
      }

      return nil
    }
    set {
      payload["iat"] = newValue?.timeIntervalSince1970
    }
  }

  public subscript(key: String) -> AnyObject? {
    get {
      return payload[key]
    }
    set {
      payload[key] = newValue
    }
  }
}

public func encode(algorithm:Algorithm, closure:(PayloadBuilder -> ())) -> String {
  let builder = PayloadBuilder()
  closure(builder)
  return encode(builder.payload, algorithm)
}
