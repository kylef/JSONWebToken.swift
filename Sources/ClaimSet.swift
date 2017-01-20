import Foundation

public struct ClaimSet {
  var claims: [String: Any]

  public init(claims: [String: Any]? = nil) {
    self.claims = claims ?? [:]
  }

  public subscript(key: String) -> Any? {
    get {
      return claims[key]
    }

    set {
      if let newValue = newValue, let date = newValue as? Date {
        claims[key] = date.timeIntervalSince1970
      } else {
        claims[key] = newValue
      }
    }
  }
}


// MARK: Accessors

extension ClaimSet {
  public var issuer: String? {
    get {
      return claims["iss"] as? String
    }

    set {
      claims["iss"] = newValue
    }
  }

  public var audience: String? {
    get {
      return claims["aud"] as? String
    }

    set {
      claims["aud"] = newValue
    }
  }

  public var expiration: Date? {
    get {
      if let expiration = claims["exp"] as? TimeInterval {
        return Date(timeIntervalSince1970: expiration)
      }

      return nil
    }

    set {
      self["exp"] = newValue
    }
  }

  public var notBefore: Date? {
    get {
      if let notBefore = claims["nbf"] as? TimeInterval {
        return Date(timeIntervalSince1970: notBefore)
      }

      return nil
    }

    set {
      self["nbf"] = newValue
    }
  }

  public var issuedAt: Date? {
    get {
      if let issuedAt = claims["iat"] as? TimeInterval {
        return Date(timeIntervalSince1970: issuedAt)
      }

      return nil
    }

    set {
      self["iat"] = newValue
    }
  }
}


// MARK: Validations

extension ClaimSet {
  public func validate(audience: String? = nil, issuer: String? = nil) throws {
    if let issuer = issuer {
      try validateIssuer(issuer)
    }

    if let audience = audience {
      try validateAudience(audience)
    }

    try validateExpiary()
    try validateNotBefore()
    try validateIssuedAt()
  }

  public func validateAudience(_ audience: String) throws {
    if let aud = self["aud"] as? [String] {
      if !aud.contains(audience) {
        throw InvalidToken.invalidAudience
      }
    } else if let aud = self["aud"] as? String {
      if aud != audience {
        throw InvalidToken.invalidAudience
      }
    } else {
      throw InvalidToken.decodeError("Invalid audience claim, must be a string or an array of strings")
    }
  }

  public func validateIssuer(_ issuer: String) throws {
    if let iss = self["iss"] as? String {
      if iss != issuer {
        throw InvalidToken.invalidIssuer
      }
    } else {
      throw InvalidToken.invalidIssuer
    }
  }

  public func validateExpiary() throws {
    try validateDate(claims, key: "exp", comparison: .orderedAscending, failure: .expiredSignature, decodeError: "Expiration time claim (exp) must be an integer")
  }

  public func validateNotBefore() throws {
    try validateDate(claims, key: "nbf", comparison: .orderedDescending, failure: .immatureSignature, decodeError: "Not before claim (nbf) must be an integer")
  }

  public func validateIssuedAt() throws {
    try validateDate(claims, key: "iat", comparison: .orderedDescending, failure: .invalidIssuedAt, decodeError: "Issued at claim (iat) must be an integer")
  }
}

// MARK: Builder

public class ClaimSetBuilder {
  var claims = ClaimSet()

  public var issuer: String? {
    get {
      return claims.issuer
    }

    set {
      claims.issuer = newValue
    }
  }

  public var audience: String? {
    get {
      return claims.audience
    }

    set {
      claims.audience = newValue
    }
  }

  public var expiration: Date? {
    get {
      return claims.expiration
    }

    set {
      claims.expiration = newValue
    }
  }

  public var notBefore: Date? {
    get {
      return claims.notBefore
    }

    set {
      claims.notBefore = newValue
    }
  }

  public var issuedAt: Date? {
    get {
      return claims.issuedAt
    }

    set {
      claims.issuedAt = newValue
    }
  }

  public subscript(key: String) -> Any? {
    get {
      return claims[key]
    }

    set {
      claims[key] = newValue
    }
  }
}

typealias PayloadBuilder = ClaimSetBuilder
