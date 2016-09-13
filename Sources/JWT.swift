import Foundation
import CryptoSwift

public typealias Payload = [String: Any]

/// The supported Algorithms
public enum Algorithm : CustomStringConvertible {
  /// No Algorithm, i-e, insecure
  case none

  /// HMAC using SHA-256 hash algorithm
  case hs256(Data)

  /// HMAC using SHA-384 hash algorithm
  case hs384(Data)

  /// HMAC using SHA-512 hash algorithm
  case hs512(Data)

  public var description:String {
    switch self {
    case .none:
      return "none"
    case .hs256:
      return "HS256"
    case .hs384:
      return "HS384"
    case .hs512:
      return "HS512"
    }
  }

  /// Sign a message using the algorithm
  func sign(_ message:String) -> String {
    func signHS(_ key: Data, variant:CryptoSwift.HMAC.Variant) -> String {
      let messageData = message.data(using: String.Encoding.utf8, allowLossyConversion: false)!
      let mac = HMAC(key: key.bytes, variant:variant)
      let result: [UInt8]
      do {
        result = try mac.authenticate(messageData.bytes)
      } catch {
        result = []
      }
      return base64encode(Data(bytes: result))
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
    }
  }

  /// Verify a signature for a message using the algorithm
  func verify(_ message:String, signature:Data) -> Bool {
    return sign(message) == base64encode(signature)
  }
}

// MARK: Encoding

/*** Encode a payload
  - parameter payload: The payload to sign
  - parameter algorithm: The algorithm to sign the payload with
  - returns: The JSON web token as a String
*/
public func encode(_ payload:Payload, algorithm:Algorithm) -> String {
  func encodeJSON(_ payload:Payload) -> String? {
    if let data = try? JSONSerialization.data(withJSONObject: payload, options: JSONSerialization.WritingOptions(rawValue: 0)) {
      return base64encode(data)
    }

    return nil
  }

  let header = encodeJSON(["typ": "JWT" as AnyObject, "alg": algorithm.description as AnyObject])!
  let payload = encodeJSON(payload)!
  let signingInput = "\(header).\(payload)"
  let signature = algorithm.sign(signingInput)
  return "\(signingInput).\(signature)"
}

open class PayloadBuilder {
  var payload = Payload()

  open var issuer:String? {
    get {
      return payload["iss"] as? String
    }
    set {
      payload["iss"] = newValue as AnyObject?
    }
  }

  open var audience:String? {
    get {
      return payload["aud"] as? String
    }
    set {
      payload["aud"] = newValue as AnyObject?
    }
  }

  open var expiration:Date? {
    get {
      if let expiration = payload["exp"] as? TimeInterval {
        return Date(timeIntervalSince1970: expiration)
      }

      return nil
    }
    set {
      payload["exp"] = newValue?.timeIntervalSince1970 as AnyObject?
    }
  }

  open var notBefore:Date? {
    get {
      if let notBefore = payload["nbf"] as? TimeInterval {
        return Date(timeIntervalSince1970: notBefore)
      }

      return nil
    }
    set {
      payload["nbf"] = newValue?.timeIntervalSince1970 as AnyObject?
    }
  }

  open var issuedAt:Date? {
    get {
      if let issuedAt = payload["iat"] as? TimeInterval {
        return Date(timeIntervalSince1970: issuedAt)
      }

      return nil
    }
    set {
      payload["iat"] = newValue?.timeIntervalSince1970 as AnyObject?
    }
  }

  open subscript(key: String) -> Any {
    get {
      return payload[key]
    }
    set {
      payload[key] = newValue
    }
  }
}

public func encode(_ algorithm:Algorithm, closure:((PayloadBuilder) -> ())) -> String {
  let builder = PayloadBuilder()
  closure(builder)
  return encode(builder.payload, algorithm: algorithm)
}
