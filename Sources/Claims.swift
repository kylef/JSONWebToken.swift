import Foundation

func validateClaims(_ payload: Payload, audience: String?, issuer: String?) throws {
  try validateIssuer(payload, issuer: issuer)
  try validateAudience(payload, audience: audience)
  try validateDate(payload, key: "exp", comparison: .orderedAscending, failure: .expiredSignature, decodeError: "Expiration time claim (exp) must be an integer")
  try validateDate(payload, key: "nbf", comparison: .orderedDescending, failure: .immatureSignature, decodeError: "Not before claim (nbf) must be an integer")
  try validateDate(payload, key: "iat", comparison: .orderedDescending, failure: .invalidIssuedAt, decodeError: "Issued at claim (iat) must be an integer")
}

func validateAudience(_ payload: Payload, audience: String?) throws {
  guard let audience = audience else {
    return
  }

  if let aud = payload["aud"] as? [String] {
    if !aud.contains(audience) {
      throw InvalidToken.invalidAudience
    }
  } else if let aud = payload["aud"] as? String {
    if aud != audience {
      throw InvalidToken.invalidAudience
    }
  } else {
    throw InvalidToken.decodeError("Invalid audience claim, must be a string or an array of strings")
  }
}

func validateIssuer(_ payload: Payload, issuer: String?) throws {
  if let issuer = issuer {
    if let iss = payload["iss"] as? String {
      if iss != issuer {
        throw InvalidToken.invalidIssuer
      }
    } else {
      throw InvalidToken.invalidIssuer
    }
  }
}

func validateDate(_ payload:Payload, key:String, comparison:ComparisonResult, failure:InvalidToken, decodeError:String) throws {
  if let timestamp = payload[key] as? TimeInterval ?? (payload[key] as? NSString)?.doubleValue as TimeInterval? {
    let date = Date(timeIntervalSince1970: timestamp)
    if date.compare(Date()) == comparison {
      throw failure
    }
  } else if payload[key] != nil {
    throw InvalidToken.decodeError(decodeError)
  }
}
