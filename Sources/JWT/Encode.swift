import Foundation

/*** Encode a set of claims
 - parameter claims: The set of claims
 - parameter algorithm: The algorithm to sign the payload with
 - returns: The JSON web token as a String
 */
public func encode(claims: ClaimSet, algorithm: Algorithm, headers: [String: String]? = nil) -> String {
  let encoder = CompactJSONEncoder()

  var headers = headers ?? [:]
  if !headers.keys.contains("typ") {
    headers["typ"] = "JWT"
  }
  headers["alg"] = algorithm.description

  let header = try! encoder.encodeString(headers)
  let payload = encoder.encodeString(claims.claims)!
  let signingInput = "\(header).\(payload)"
  let signature = algorithm.sign(signingInput)
  return "\(signingInput).\(signature)"
}

/*** Encode a dictionary of claims
 - parameter claims: The dictionary of claims
 - parameter algorithm: The algorithm to sign the payload with
 - returns: The JSON web token as a String
 */
public func encode(claims: [String: Any], algorithm: Algorithm, headers: [String: String]? = nil) -> String {
  return encode(claims: ClaimSet(claims: claims), algorithm: algorithm, headers: headers)
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
