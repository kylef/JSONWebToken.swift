import Foundation


/// Failure reasons from decoding a JWT
public enum InvalidToken: CustomStringConvertible, Error {
  /// Decoding the JWT itself failed
  case decodeError(String)

  /// The JWT uses an unsupported algorithm
  case invalidAlgorithm

  /// The issued claim has expired
  case expiredSignature

  /// The issued claim is for the future
  case immatureSignature

  /// The claim is for the future
  case invalidIssuedAt

  /// The audience of the claim doesn't match
  case invalidAudience

  /// The issuer claim failed to verify
  case invalidIssuer

  /// Returns a readable description of the error
  public var description: String {
    switch self {
    case .decodeError(let error):
      return "Decode Error: \(error)"
    case .invalidIssuer:
      return "Invalid Issuer"
    case .expiredSignature:
      return "Expired Signature"
    case .immatureSignature:
      return "The token is not yet valid (not before claim)"
    case .invalidIssuedAt:
      return "Issued at claim (iat) is in the future"
    case .invalidAudience:
      return "Invalid Audience"
    case .invalidAlgorithm:
      return "Unsupported algorithm or incorrect key"
    }
  }
}


/// Decode a JWT
public func decode(_ jwt: String, algorithms: [Algorithm], verify: Bool = true, audience: String? = nil, issuer: String? = nil, leeway: TimeInterval = 0) throws -> ClaimSet {
  let (header, claims, signature, signatureInput) = try load(jwt)

  if verify {
    try claims.validate(audience: audience, issuer: issuer, leeway: leeway)
    try verifySignature(algorithms, header: header, signingInput: signatureInput, signature: signature)
  }

  return claims
}

/// Decode a JWT
public func decode(_ jwt: String, algorithm: Algorithm, verify: Bool = true, audience: String? = nil, issuer: String? = nil, leeway: TimeInterval = 0) throws -> ClaimSet {
  return try decode(jwt, algorithms: [algorithm], verify: verify, audience: audience, issuer: issuer, leeway: leeway)
}

// MARK: Parsing a JWT

func load(_ jwt: String) throws -> (header: JOSEHeader, payload: ClaimSet, signature: Data, signatureInput: String) {
  let segments = jwt.components(separatedBy: ".")
  if segments.count != 3 {
    throw InvalidToken.decodeError("Not enough segments")
  }

  let headerSegment = segments[0]
  let payloadSegment = segments[1]
  let signatureSegment = segments[2]
  let signatureInput = "\(headerSegment).\(payloadSegment)"

  let decoder = CompactJSONDecoder()
  let header = try decoder.decode(JOSEHeader.self, from: headerSegment)
  let payload = try decoder.decode(from: payloadSegment)

  guard let signature = base64decode(signatureSegment) else {
    throw InvalidToken.decodeError("Signature is not correctly encoded as base64")
  }

  return (header: header, payload: ClaimSet(claims: payload), signature: signature, signatureInput: signatureInput)
}

// MARK: Signature Verification

func verifySignature(_ algorithms: [Algorithm], header: JOSEHeader, signingInput: String, signature: Data) throws {
  guard let alg = header.algorithm else {
    throw InvalidToken.decodeError("Missing Algorithm")
  }

  let verifiedAlgorithms = algorithms
    .filter { algorithm in algorithm.description == alg }
    .filter { algorithm in algorithm.algorithm.verify(signingInput.data(using: .utf8)!, signature: signature) }

  if verifiedAlgorithms.isEmpty {
    throw InvalidToken.invalidAlgorithm
  }
}
