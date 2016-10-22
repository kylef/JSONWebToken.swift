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
  public var description:String {
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
public func decode(_ jwt: String, algorithms: [Algorithm], verify: Bool = true, audience: String? = nil, issuer: String? = nil) throws -> Payload {

  let (header, payload, signature, signatureInput) = try load(jwt)
  if verify {
    try validateClaims(payload: payload, audience: audience, issuer: issuer)
    try verifySignature(algorithms, header: header, signingInput: signatureInput, signature: signature)
  }
  return payload
}

/// Decode a JWT
public func decode(_ jwt: String, algorithm: Algorithm, verify: Bool = true, audience: String? = nil, issuer: String? = nil) throws -> Payload {
  return try decode(jwt, algorithms: [algorithm], verify: verify, audience: audience, issuer: issuer)
}

// MARK: Parsing a JWT

typealias LoadedToken = (header: Payload, payload: Payload, signature: Data, signatureInput: String)

func load(_ jwt: String) throws -> LoadedToken {
  let segments = jwt.components(separatedBy: ".")
  guard segments.count == 3 else {
    throw InvalidToken.decodeError("Not enough segments")
  }

  let headerSegment = segments[0]
  let payloadSegment = segments[1]
  let signatureSegment = segments[2]
  let signatureInput = "\(headerSegment).\(payloadSegment)"

  guard let headerData = base64decode(headerSegment) else {
    throw InvalidToken.decodeError("Header is not correctly encoded as base64")
  }

  guard let header = try Payload(jsonData: headerData) else {
    throw InvalidToken.decodeError("Invalid header")
  }

  guard let payloadData = base64decode(payloadSegment) else {
    throw InvalidToken.decodeError("Payload is not correctly encoded as base64")
  }

  guard let payload = try Payload(jsonData: payloadData) else {
    throw InvalidToken.decodeError("Invalid payload")
  }

  guard let signature = base64decode(signatureSegment) else {
    throw InvalidToken.decodeError("Signature is not correctly encoded as base64")
  }

  return (header: header, payload: payload, signature: signature, signatureInput: signatureInput)
}

// MARK: Signature Verification

func verifySignature(_ algorithms: [Algorithm], header: Payload, signingInput: String, signature: Data) throws {
  guard let algorithmDescription: String = header["alg"] else {
    throw InvalidToken.decodeError("Missing Algorithm")
  }

  let verifiedAlgorithmsMatchingDescription = algorithms
    .filter { algorithm in algorithm.description == algorithmDescription }
    .filter { algorithm in algorithm.verify(signingInput, signature: signature) }

  if verifiedAlgorithmsMatchingDescription.count == 0 {
    throw InvalidToken.invalidAlgorithm
  }
}
