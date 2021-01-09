import Foundation
import Crypto


extension HMACAlgorithm: SignAlgorithm, VerifyAlgorithm {
  var symmetricKey: SymmetricKey {
    return SymmetricKey(data: key)
  }

  public func sign(_ message: Data) -> Data {
    switch hash {
    case .sha256:
      let code = HMAC<SHA256>.authenticationCode(for: message, using: symmetricKey)
      return Data(code)
    case .sha384:
      let code = HMAC<SHA384>.authenticationCode(for: message, using: symmetricKey)
      return Data(code)
    case .sha512:
      let code = HMAC<SHA512>.authenticationCode(for: message, using: symmetricKey)
      return Data(code)
    }
  }

  public func verify(_ message: Data, signature: Data) -> Bool {
    switch hash {
    case .sha256:
      return HMAC<SHA256>.isValidAuthenticationCode(signature, authenticating: message, using: symmetricKey)
    case .sha384:
      return HMAC<SHA384>.isValidAuthenticationCode(signature, authenticating: message, using: symmetricKey)
    case .sha512:
      return HMAC<SHA512>.isValidAuthenticationCode(signature, authenticating: message, using: symmetricKey)
    }
  }
}
