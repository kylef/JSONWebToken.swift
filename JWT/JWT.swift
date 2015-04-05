import Foundation
import CryptoSwift

public typealias Payload = [String:AnyObject]

public enum InvalidToken : Printable {
  case DecodeError(String)
  case InvalidIssuer
  case ExpiredSignature
  case ImmatureSignature
  case InvalidIssuedAt
  case InvalidAudience

  case InvalidAlgorithm
  case InvalidKey

  public var description:String {
    switch self {
      case .DecodeError(let error):
        return "Decode Error: \(error)"
      case .InvalidIssuer:
        return "Invalid Issuer"
      case .ExpiredSignature:
        return "Expired Signature"
      case .ImmatureSignature:
        return "The token is not yet valid (not before claim)"
      case .InvalidIssuedAt:
        return "Issued at claim (iat) is in the future"
      case InvalidAudience:
        return "Invalid Audience"
      case InvalidAlgorithm:
        return "Unsupported Algorithm"
      case InvalidKey:
        return "Invalid Key"
    }
  }
}

/// The supported Algorithms
public enum Algorithm : Printable {
  /// No Algorithm, i-e, insecure
  case None

  /// HMAC using SHA-256 hash algorithm
  case HS256(String)

  static func algorithm(name:String, key:String?) -> Algorithm? {
    if name == "none" {
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

  func verify(message:String, signature:NSData) -> Bool {
    return sign(message) == base64encode(signature)
  }
}

public enum DecodeResult {
  case Success(Payload)
  case Failure(InvalidToken)
}


/// Decode a JWT
public func decode(jwt:String, key:String? = nil, verify:Bool = true, audience:String? = nil, issuer:String? = nil) -> DecodeResult {
  switch load(jwt) {
    case let .Success(header, payload, signature, signatureInput):
      if verify {
        if let failure = validateClaims(payload, audience, issuer) ?? verifySignature(header, signatureInput, signature, key) {
          return .Failure(failure)
        }
      }

      return .Success(payload)
    case .Failure(let failure):
      return .Failure(failure)
  }
}


/// Encoding a payload
public func encode(payload:Payload, algorithm:Algorithm) -> String {
  func encode(payload:Payload) -> String? {
    if let data = NSJSONSerialization.dataWithJSONObject(payload, options: NSJSONWritingOptions(0), error: nil) {
      return base64encode(data)
    }

    return nil
  }

  let header = encode(["typ": "JWT", "alg": algorithm.description])!
  let payload = encode(payload)!
  let signingInput = "\(header).\(payload)"
  let signature = algorithm.sign(signingInput)
  return "\(signingInput).\(signature)"
}

// MARK: Parsing a JWT

enum LoadResult {
  case Success(header:Payload, payload:Payload, signature:NSData, signatureInput:String)
  case Failure(InvalidToken)
}

/// URL Base64 Decoding

func base64encode(input:NSData) -> String {
  let data = input.base64EncodedDataWithOptions(NSDataBase64EncodingOptions(0))
  let string = NSString(data: data, encoding: NSUTF8StringEncoding) as String
  return string
    .stringByReplacingOccurrencesOfString("+", withString: "-", options: NSStringCompareOptions(0), range: nil)
    .stringByReplacingOccurrencesOfString("/", withString: "_", options: NSStringCompareOptions(0), range: nil)
    .stringByReplacingOccurrencesOfString("=", withString: "", options: NSStringCompareOptions(0), range: nil)
}

func base64decode(input:String) -> NSData? {
  let rem = countElements(input) % 4

  var ending = ""
  if rem > 0 {
    let amount = 4 - rem
    ending = String(count: amount, repeatedValue: Character("="))
  }

  let base64 = input.stringByReplacingOccurrencesOfString("-", withString: "+", options: NSStringCompareOptions(0), range: nil)
    .stringByReplacingOccurrencesOfString("_", withString: "/", options: NSStringCompareOptions(0), range: nil) + ending

  return NSData(base64EncodedString: base64, options: NSDataBase64DecodingOptions(0))
}

func load(jwt:String) -> LoadResult {
  let segments = jwt.componentsSeparatedByString(".")
  if segments.count != 3 {
    return .Failure(.DecodeError("Not enough segments"))
  }

  let headerSegment = segments[0]
  let payloadSegment = segments[1]
  let signatureSegment = segments[2]
  let signatureInput = "\(headerSegment).\(payloadSegment)"

  let headerData = base64decode(headerSegment)
  if headerData == nil {
    return .Failure(.DecodeError("Header is not correctly encoded as base64"))
  }

  let header = NSJSONSerialization.JSONObjectWithData(headerData!, options: NSJSONReadingOptions(0), error: nil) as? Payload
  if header == nil {
    return .Failure(.DecodeError("Invalid header"))
  }

  let payloadData = base64decode(payloadSegment)
  if payloadData == nil {
    return .Failure(.DecodeError("Payload is not correctly encoded as base64"))
  }

  let payload = NSJSONSerialization.JSONObjectWithData(payloadData!, options: NSJSONReadingOptions(0), error: nil) as? Payload
  if payload == nil {
    return .Failure(.DecodeError("Invalid payload"))
  }

  let signature = base64decode(signatureSegment)
  if signature == nil {
    return .Failure(.DecodeError("Signature is not correctly encoded as base64"))
  }

  return .Success(header:header!, payload:payload!, signature:signature!, signatureInput:signatureInput)
}

// MARK: Signature Verification

func verifySignature(header:Payload, signingInput:String, signature:NSData, key:String?) -> InvalidToken? {
  if let alg = header["alg"] as? String {
    if let algoritm = Algorithm.algorithm(alg, key: key) {
      if algoritm.verify(signingInput, signature: signature) {
        return nil
      } else {
        return .DecodeError("Signature verification failed")
      }
    }

    return .InvalidAlgorithm
  }

  return .DecodeError("Missing Algorithm")
}
