import Foundation
import CryptoSwift

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
  func verify(_ message: String, signature: Data) -> Bool {
    return sign(message) == base64encode(signature)
  }
}

/// Encode a payload
///
/// - parameter payload:   The payload to sign
/// - parameter algorithm: The algorithm to sign the payload with
///
/// - throws: when serialization fails
///
/// - returns: The JSON web token as a String
public func encode(_ payload: Payload, algorithm: Algorithm) throws -> String {
  func encodeJSON(_ payload: Payload) throws -> String {
    let data = try JSONSerialization.data(withJSONObject: payload.store, options: JSONSerialization.WritingOptions(rawValue: 0))
    return base64encode(data)
  }

  let header = try encodeJSON(["typ": "JWT", "alg": algorithm.description])
  let payload = try encodeJSON(payload)
  let signingInput = "\(header).\(payload)"
  let signature = algorithm.sign(signingInput)
  return "\(signingInput).\(signature)"
}

public struct Payload: ExpressibleByDictionaryLiteral {

  typealias BackingStore = [String: Any]

  var store: BackingStore = [:]

  public init(dictionaryLiteral elements: (String, Any)...) {
    for (key, value) in elements {
      store[key] = value
    }
  }

  init?(jsonData: Data) throws {
    guard let store = try JSONSerialization.jsonObject(with: jsonData) as? BackingStore else {
      return nil
    }
    self.store = store
  }

  public var issuer: String? {
    get {
      return self["iss"]
    }
    set {
      self["iss"] = newValue
    }
  }

  public var audience: String? {
    get {
      return self["aud"]
    }
    set {
      self["aud"] = newValue
    }
  }

  public var audiences: [String]? {
    get {
      return self["aud"] ?? audience.map { [$0] }
    }
    set {
      self["aud"] = newValue
    }
  }

  public var expiration: Date? {
    get {
      return self["exp"]
    }
    set {
      self["exp"] = newValue
    }
  }

  public var notBefore: Date? {
    get {
      return self["nbf"]
    }
    set {
      self["nbf"] = newValue
    }
  }

  public var issuedAt: Date? {
    get {
      return self["iat"]
    }
    set {
      self["iat"] = newValue
    }
  }

  public subscript(key: String) -> Any {
    get {
      return store[key]
    }
    set {
      store[key] = newValue
    }
  }

  public subscript(key: String) -> Date? {
    get {
      guard let timeInterval = store[key] as? TimeInterval ??
      (store[key] as? NSString)?.doubleValue else {
        return nil
      }
      return Date.init(timeIntervalSince1970: timeInterval)
    }
    set {
      store[key] = newValue?.timeIntervalSince1970
    }
  }

  public subscript(key: String) -> String? {
    get {
      return store[key] as? String
    }
    set {
      store[key] = newValue
    }
  }

  public subscript(key: String) -> [String]? {
    get {
      return store[key] as? [String]
    }
    set {
      store[key] = newValue
    }
  }
}
