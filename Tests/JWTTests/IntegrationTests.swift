import XCTest
import JWT

class IntegrationTests: XCTestCase {
  func testVerificationFailureWithoutLeeway() {
    let token = JWT.encode(.none) { builder in
      builder.issuer = "fuller.li"
      builder.audience = "cocoapods"
      builder.expiration = Date().addingTimeInterval(-1) // Token expired one second ago
      builder.notBefore = Date().addingTimeInterval(1) // Token starts being valid in one second
      builder.issuedAt = Date().addingTimeInterval(1) // Token is issued one second in the future
    }

    do {
      let _ = try JWT.decode(token, algorithm: .none, leeway: 0)
      XCTFail("InvalidToken error should have been thrown.")
    } catch is InvalidToken {
      // Correct error thrown
    } catch {
      XCTFail("Unexpected error type while verifying token.")
    }
  }

  func testVerificationSuccessWithLeeway() {
    let token = JWT.encode(.none) { builder in
      builder.issuer = "fuller.li"
      builder.audience = "cocoapods"
      builder.expiration = Date().addingTimeInterval(-1) // Token expired one second ago
      builder.notBefore = Date().addingTimeInterval(1) // Token starts being valid in one second
      builder.issuedAt = Date().addingTimeInterval(1) // Token is issued one second in the future
    }

    do {
      let _ = try JWT.decode(token, algorithm: .none, leeway: 2)
      // Due to leeway no error gets thrown.
    } catch {
      XCTFail("Unexpected error type while verifying token.")
    }
  }
}
