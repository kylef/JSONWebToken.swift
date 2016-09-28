import Foundation

func validateClaims(payload: Payload, audience: String?, issuer: String?) throws {
  try validateIssuer(payload: payload, issuer: issuer)
  try validateAudience(payload: payload, audience: audience)
  try validateDate(payload: payload, key: "exp", comparison: .orderedAscending, failure: .expiredSignature)
  try validateDate(payload: payload, key: "nbf", comparison: .orderedDescending, failure: .immatureSignature)
  try validateDate(payload: payload, key: "iat", comparison: .orderedDescending, failure: .invalidIssuedAt)
}

func validateAudience(payload: Payload, audience: String?) throws {
  guard let audience = audience else {
    return
  }

  guard let audiences = payload.audiences else {
    throw InvalidToken.decodeError("Invalid audience claim, must be a string or an array of strings")
  }

  if !audiences.contains(audience) {
    throw InvalidToken.invalidAudience
  }
}

func validateIssuer(payload: Payload, issuer: String?) throws {
  if let issuer = issuer, issuer != payload.issuer {
    throw InvalidToken.invalidIssuer
  }
}

func validateDate(payload: Payload, key: String, comparison: ComparisonResult, failure: InvalidToken) throws {
  guard let validationDate: Date = payload[key] else {
    if payload.store[key] != nil {
      throw InvalidToken.decodeError("Incorrect date claim value for key: '\(key)'")
    }
    return
  }

  if validationDate.compare(Date()) == comparison {
    throw failure
  }
}
