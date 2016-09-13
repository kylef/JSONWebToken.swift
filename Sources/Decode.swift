import Foundation


/// Failure reasons from decoding a JWT
public enum InvalidToken : CustomStringConvertible, Error {
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
public func decode(_ jwt:String, algorithms:[Algorithm], verify:Bool = true, audience:String? = nil, issuer:String? = nil) throws -> Payload {
  switch load(jwt) {
  case let .success(header, payload, signature, signatureInput):
    if verify {
      if let failure = validateClaims(payload, audience: audience, issuer: issuer) ?? verifySignature(algorithms, header: header, signingInput: signatureInput, signature: signature) {
        throw failure
      }
    }

    return payload
  case .failure(let failure):
    throw failure
  }
}

/// Decode a JWT
public func decode(_ jwt:String, algorithm:Algorithm, verify:Bool = true, audience:String? = nil, issuer:String? = nil) throws -> Payload {
  return try decode(jwt, algorithms: [algorithm], verify: verify, audience: audience, issuer: issuer)
}

// MARK: Parsing a JWT

enum LoadResult {
  case success(header:Payload, payload:Payload, signature:Data, signatureInput:String)
  case failure(InvalidToken)
}

func load(_ jwt:String) -> LoadResult {
  let segments = jwt.components(separatedBy: ".")
  if segments.count != 3 {
    return .failure(.decodeError("Not enough segments"))
  }

  let headerSegment = segments[0]
  let payloadSegment = segments[1]
  let signatureSegment = segments[2]
  let signatureInput = "\(headerSegment).\(payloadSegment)"

  let headerData = base64decode(headerSegment)
  if headerData == nil {
    return .failure(.decodeError("Header is not correctly encoded as base64"))
  }

  let header = (try? JSONSerialization.jsonObject(with: headerData!, options: JSONSerialization.ReadingOptions(rawValue: 0))) as? Payload
  if header == nil {
    return .failure(.decodeError("Invalid header"))
  }

  let payloadData = base64decode(payloadSegment)
  if payloadData == nil {
    return .failure(.decodeError("Payload is not correctly encoded as base64"))
  }

  let payload = (try? JSONSerialization.jsonObject(with: payloadData!, options: JSONSerialization.ReadingOptions(rawValue: 0))) as? Payload
  if payload == nil {
    return .failure(.decodeError("Invalid payload"))
  }

  let signature = base64decode(signatureSegment)
  if signature == nil {
    return .failure(.decodeError("Signature is not correctly encoded as base64"))
  }

  return .success(header:header!, payload:payload!, signature:signature!, signatureInput:signatureInput)
}

// MARK: Signature Verification

func verifySignature(_ algorithms:[Algorithm], header:Payload, signingInput:String, signature:Data) -> InvalidToken? {
  if let alg = header["alg"] as? String {
    let matchingAlgorithms = algorithms.filter { algorithm in  algorithm.description == alg }
    let results = matchingAlgorithms.map { algorithm in algorithm.verify(signingInput, signature: signature) }
    let successes = results.filter { $0 }
    if successes.count > 0 {
      return nil
    }

    return .invalidAlgorithm
  }

  return .decodeError("Missing Algorithm")
}
