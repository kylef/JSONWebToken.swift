import Foundation


/// Represents a JSON Web Algorithm (JWA)
/// https://tools.ietf.org/html/draft-ietf-jose-json-web-algorithms-40
public protocol Algorithm: class {
  var name: String { get }
}


// MARK: Signing

/// Represents a JSON Web Algorithm (JWA) that is capable of signing
public protocol SignAlgorithm: Algorithm {
  func sign(_ message: Data) -> Data
}


// MARK: Verifying

/// Represents a JSON Web Algorithm (JWA) that is capable of verifying
public protocol VerifyAlgorithm: Algorithm {
  func verify(_ message: Data, signature: Data) -> Bool
}


extension SignAlgorithm {
  /// Verify a signature for a message using the algorithm
  public func verify(_ message: Data, signature: Data) -> Bool {
    return sign(message) == signature
  }
}
