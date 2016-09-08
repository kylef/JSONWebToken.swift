import Foundation

func validateClaims(payload:Payload, audience:String?, issuer:String?) -> InvalidToken? {
  return validateIssuer(payload: payload, issuer: issuer) ?? validateAudience(payload: payload, audience: audience) ??
    validateDate(payload: payload, key: "exp", comparison: .orderedAscending, failure: .expiredSignature, decodeError: "Expiration time claim (exp) must be an integer") ??
    validateDate(payload: payload, key: "nbf", comparison: .orderedDescending, failure: .immatureSignature, decodeError: "Not before claim (nbf) must be an integer") ??
    validateDate(payload: payload, key: "iat", comparison: .orderedDescending, failure: .invalidIssuedAt, decodeError: "Issued at claim (iat) must be an integer")
}

func validateAudience(payload:Payload, audience:String?) -> InvalidToken? {
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

func validateIssuer(payload:Payload, issuer:String?) -> InvalidToken? {
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

func validateDate(payload:Payload, key:String, comparison:ComparisonResult, failure:InvalidToken, decodeError:String) -> InvalidToken? {
  
  if let value = payload[key] {
    var date: Date?
    
    if let interval = value as? Double {
      date = Date(timeIntervalSince1970: interval)
    } else if let timestamp = value as? String, let interval = Double(timestamp) {
      date = Date(timeIntervalSince1970: interval)
    }
    
    if date != nil {
      if date!.compare(Date()) == comparison {
        return failure
      }
    } else {
      return .decodeError(decodeError)
    }
  }
  
  return nil
  
}
