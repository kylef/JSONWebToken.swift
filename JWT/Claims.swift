import Foundation

func validateClaims(payload:Payload, audience:String?, issuer:String?) -> InvalidToken? {
  return validateIssuer(payload, issuer: issuer) ?? validateAudience(payload, audience: audience) ??
    validateDate(payload, key: "exp", comparison: .OrderedAscending, failure: .ExpiredSignature, decodeError: "Expiration time claim (exp) must be an integer") ??
    validateDate(payload, key: "nbf", comparison: .OrderedDescending, failure: .ImmatureSignature, decodeError: "Not before claim (nbf) must be an integer") ??
    validateDate(payload, key: "iat", comparison: .OrderedDescending, failure: .InvalidIssuedAt, decodeError: "Issued at claim (iat) must be an integer")
}

func validateAudience(payload:Payload, audience:String?) -> InvalidToken? {
  if let audience = audience {
    if let aud = payload["aud"] as? [String] {
      if !aud.contains(audience) {
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
  if let timestamp = payload[key] as? NSTimeInterval ?? payload[key]?.doubleValue as NSTimeInterval? {
    let date = NSDate(timeIntervalSince1970: timestamp)
    if date.compare(NSDate()) == comparison {
      return failure
    }
  } else if payload[key] != nil {
    return .DecodeError(decodeError)
  }

  return nil
}
