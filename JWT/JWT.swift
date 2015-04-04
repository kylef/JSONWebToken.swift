import Foundation

public typealias Payload = [String:AnyObject]

public enum InvalidToken : Printable {
  case DecodeError(String)
  case InvalidIssuer
  case ExpiredSignature
  case ImmatureSignature
  case InvalidIssuedAt
  case InvalidAudience

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
    }
  }
}

public enum DecodeResult {
  case Success(Payload)
  case Failure(InvalidToken)
}


/// Decode a JWT
public func decode(jwt:String, verify:Bool = true, audience:String? = nil, issuer:String? = nil) -> DecodeResult {
  switch load(jwt) {
    case let .Success(header, payload, signature, signatureInput):
      if verify {
        if let failure = validateClaims(payload, audience, issuer) {
          return .Failure(failure)
        }
      }

      return .Success(payload)
    case .Failure(let failure):
      return .Failure(failure)
  }
}

// MARK: Parsing a JWT

enum LoadResult {
  case Success(header:Payload, payload:Payload, signature:NSData, signatureInput:String)
  case Failure(InvalidToken)
}

/// URL Base64 Decoding
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

// MARK: Validation

func validateAudience(payload:Payload, audience:String?) -> InvalidToken? {
  if let audience = audience {
    if let aud = payload["aud"] as? [String] {
      if !contains(aud, audience) {
        return .InvalidAudience
      }
    } else if let aud = payload["aud"] as? String {
      if aud != audience {
        return .InvalidAudience
      }
    } else {
      return .DecodeError("Invalid audience claim, must be a string or an array of strings")
    }
  }

  return nil
}

func validateIssuer(payload:Payload, issuer:String?) -> InvalidToken? {
  if let issuer = issuer {
    if let iss = payload["iss"] as? String {
      if iss != issuer {
        return .InvalidIssuer
      }
    } else {
      return .InvalidIssuer
    }
  }

  return nil
}

func validateDate(payload:Payload, key:String, comparison:NSComparisonResult, failure:InvalidToken, decodeError:String) -> InvalidToken? {
  if let timestamp = payload[key] as? NSTimeInterval {
    let date = NSDate(timeIntervalSince1970: timestamp)
    if date.compare(NSDate()) == comparison {
      return failure
    }
  } else if let timestamp:AnyObject = payload[key] {
    return .DecodeError(decodeError)
  }

  return nil
}

func validateClaims(payload:Payload, audience:String?, issuer:String?) -> InvalidToken? {
  return validateIssuer(payload, issuer) ?? validateAudience(payload, audience) ??
    validateDate(payload, "exp", .OrderedAscending, .ExpiredSignature, "Expiration time claim (exp) must be an integer") ??
    validateDate(payload, "nbf", .OrderedDescending, .ImmatureSignature, "Not before claim (nbf) must be an integer") ??
    validateDate(payload, "iat", .OrderedDescending, .InvalidIssuedAt, "Issued at claim (iat) must be an integer")
}
