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
  if payload[key] == nil {
    return
  }

  guard let date = extractDate(payload: payload, key: key) else {
    throw InvalidToken.decodeError(decodeError)
  }

  if date.compare(Date()) == comparison {
    throw failure
  }
}

fileprivate func extractDate(payload: Payload, key: String) -> Date? {
  if let timestamp = payload[key] as? TimeInterval {
    return Date(timeIntervalSince1970: timestamp)
  }

  if let timestamp = payload[key] as? Int {
    return Date(timeIntervalSince1970: Double(timestamp))
  }

  if let timestampString = payload[key] as? String, let timestamp = Double(timestampString) {
    return Date(timeIntervalSince1970: timestamp)
  }

  return nil
}
