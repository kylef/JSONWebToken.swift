import Foundation


/// Failure reasons from decoding a JWT
public enum InvalidToken : Printable {
  /// Decoding the JWT itself failed
  case DecodeError(String)

  /// The JWT uses an unsupported algorithm
  case InvalidAlgorithm

  /// An invalid key was used when trying to validate a JWT
  case InvalidKey

  /// The issued claim has expired
  case ExpiredSignature

  /// The issued claim is for the future
  case ImmatureSignature

  /// The claim is for the future
  case InvalidIssuedAt

  /// The audience of the claim doesn't match
  case InvalidAudience

  /// The issuer claim failed to verify
  case InvalidIssuer

  /// Returns a readable description of the error
  public var description:String {
    switch self {
    case .DecodeError(let error):
      return "Decode Error: \(error)"
    case .InvalidIssuer:
      return "Invalid Issuer"
    case .ExpiredSignature:
      return "Expired Signature"
    case .ImmatureSignature:
      return "The token is not yet valid (not before claim)"
    case .InvalidIssuedAt:
      return "Issued at claim (iat) is in the future"
    case InvalidAudience:
      return "Invalid Audience"
    case InvalidAlgorithm:
      return "Unsupported Algorithm"
    case InvalidKey:
      return "Invalid Key"
    }
  }
}


/// Result from decoding a JWT
public enum DecodeResult {
  /// Decoding succeeded
  case Success(Payload)

  /// Decoding failed, take a look at the invalid token reason
  case Failure(InvalidToken)
}


/// Decode a JWT
public func decode(jwt:String, key:String? = nil, verify:Bool = true, audience:String? = nil, issuer:String? = nil) -> DecodeResult {
  switch load(jwt) {
  case let .Success(header, payload, signature, signatureInput):
    if verify {
      if let failure = validateClaims(payload, audience, issuer) ?? verifySignature(header, signatureInput, signature, key) {
        return .Failure(failure)
      }
    }

    return .Success(payload)
  case .Failure(let failure):
    return .Failure(failure)
  }
}

// MARK: Parsing a JWT

enum LoadResult {
  case Success(header:Payload, payload:Payload, signature:NSData, signatureInput:String)
  case Failure(InvalidToken)
}

func load(jwt:String) -> LoadResult {
  let segments = jwt.componentsSeparatedByString(".")
  if segments.count != 3 {
    return .Failure(.DecodeError("Not enough segments"))
  }

  let headerSegment = segments[0]
  let payloadSegment = segments[1]
  let signatureSegment = segments[2]
  let signatureInput = "\(headerSegment).\(payloadSegment)"

  let headerData = base64decode(headerSegment)
  if headerData == nil {
    return .Failure(.DecodeError("Header is not correctly encoded as base64"))
  }

  let header = NSJSONSerialization.JSONObjectWithData(headerData!, options: NSJSONReadingOptions(0), error: nil) as? Payload
  if header == nil {
    return .Failure(.DecodeError("Invalid header"))
  }

  let payloadData = base64decode(payloadSegment)
  if payloadData == nil {
    return .Failure(.DecodeError("Payload is not correctly encoded as base64"))
  }

  let payload = NSJSONSerialization.JSONObjectWithData(payloadData!, options: NSJSONReadingOptions(0), error: nil) as? Payload
  if payload == nil {
    return .Failure(.DecodeError("Invalid payload"))
  }

  let signature = base64decode(signatureSegment)
  if signature == nil {
    return .Failure(.DecodeError("Signature is not correctly encoded as base64"))
  }

  return .Success(header:header!, payload:payload!, signature:signature!, signatureInput:signatureInput)
}

// MARK: Signature Verification

func verifySignature(header:Payload, signingInput:String, signature:NSData, key:String?) -> InvalidToken? {
  if let alg = header["alg"] as? String {
    if let algoritm = Algorithm.algorithm(alg, key: key) {
      if algoritm.verify(signingInput, signature: signature) {
        return nil
      } else {
        return .InvalidKey
      }
    }

    return .InvalidAlgorithm
  }

  return .DecodeError("Missing Algorithm")
}
