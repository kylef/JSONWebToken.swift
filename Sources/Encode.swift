import Foundation

/*** Encode a set of claims
 - parameter claims: The set of claims
 - parameter algorithm: The algorithm to sign the payload with
 - returns: The JSON web token as a String
 */
public func encode(claims: ClaimSet, algorithm: Algorithm) -> String {
  func encodeJSON(_ payload: [String: Any]) -> String? {
    if let data = try? JSONSerialization.data(withJSONObject: payload) {
      return base64encode(data)
    }

    return nil
  }

  let header = encodeJSON(["typ": "JWT", "alg": algorithm.description])!
  let payload = encodeJSON(claims.claims)!
  let signingInput = "\(header).\(payload)"
  let signature = algorithm.sign(signingInput)
  return "\(signingInput).\(signature)"
}

/*** Encode a dictionary of claims
 - parameter claims: The dictionary of claims
 - parameter algorithm: The algorithm to sign the payload with
 - returns: The JSON web token as a String
 */
public func encode(claims: [String: Any], algorithm: Algorithm) -> String {
  return encode(claims: ClaimSet(claims: claims), algorithm: algorithm)
}


/// Encode a set of claims using the builder pattern
public func encode(_ algorithm: Algorithm, closure: ((ClaimSetBuilder) -> Void)) -> String {
  let builder = ClaimSetBuilder()
  closure(builder)
  return encode(claims: builder.claims, algorithm: algorithm)
}


/*** Encode a payload
 - parameter payload: The payload to sign
 - parameter algorithm: The algorithm to sign the payload with
 - returns: The JSON web token as a String
 */
@available(*, deprecated, message: "use encode(claims: algorithm:) instead")
public func encode(_ payload: Payload, algorithm: Algorithm) -> String {
  return encode(claims: ClaimSet(claims: payload), algorithm: algorithm)
}
