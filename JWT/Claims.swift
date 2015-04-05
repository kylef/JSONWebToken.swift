import Foundation

func validateClaims(payload:Payload, audience:String?, issuer:String?) -> InvalidToken? {
  return validateIssuer(payload, issuer) ?? validateAudience(payload, audience) ??
    validateDate(payload, "exp", .OrderedAscending, .ExpiredSignature, "Expiration time claim (exp) must be an integer") ??
    validateDate(payload, "nbf", .OrderedDescending, .ImmatureSignature, "Not before claim (nbf) must be an integer") ??
    validateDate(payload, "iat", .OrderedDescending, .InvalidIssuedAt, "Issued at claim (iat) must be an integer")
}

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
