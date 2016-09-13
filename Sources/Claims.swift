import Foundation

func validateClaims(_ payload:Payload, audience:String?, issuer:String?) -> InvalidToken? {
  return validateIssuer(payload, issuer: issuer) ?? validateAudience(payload, audience: audience) ??
    validateDate(payload, key: "exp", comparison: .orderedAscending, failure: .expiredSignature, decodeError: "Expiration time claim (exp) must be an integer") ??
    validateDate(payload, key: "nbf", comparison: .orderedDescending, failure: .immatureSignature, decodeError: "Not before claim (nbf) must be an integer") ??
    validateDate(payload, key: "iat", comparison: .orderedDescending, failure: .invalidIssuedAt, decodeError: "Issued at claim (iat) must be an integer")
}

func validateAudience(_ payload:Payload, audience:String?) -> InvalidToken? {
  if let audience = audience {
    if let aud = payload["aud"] as? [String] {
      if !aud.contains(audience) {
        return .invalidAudience
      }
    } else if let aud = payload["aud"] as? String {
      if aud != audience {
        return .invalidAudience
      }
    } else {
      return .decodeError("Invalid audience claim, must be a string or an array of strings")
    }
  }

  return nil
}

func validateIssuer(_ payload:Payload, issuer:String?) -> InvalidToken? {
  if let issuer = issuer {
    if let iss = payload["iss"] as? String {
      if iss != issuer {
        return .invalidIssuer
      }
    } else {
      return .invalidIssuer
    }
  }

  return nil
}

func validateDate(_ payload:Payload, key:String, comparison:ComparisonResult, failure:InvalidToken, decodeError:String) -> InvalidToken? {
  if let timestamp = payload[key] as? TimeInterval ?? (payload[key] as? NSString)?.doubleValue as TimeInterval? {
    let date = Date(timeIntervalSince1970: timestamp)
    if date.compare(Date()) == comparison {
      return failure
    }
  } else if payload[key] != nil {
    return .decodeError(decodeError)
  }

  return nil
}
