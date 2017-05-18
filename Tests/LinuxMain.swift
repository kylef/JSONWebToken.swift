import XCTest
@testable import JWTTests


extension EncodeTests {
  static var allTests: [(String, (EncodeTests) -> (Void) throws -> Void)] {
    return [
      ("testEncodingJWT", testEncodingJWT),
      ("testEncodingWithBuilder", testEncodingWithBuilder),
    ]
  }
}

extension DecodeTests {
  static var allTests: [(String, (DecodeTests) -> (Void) throws -> Void)] {
    return [
      ("testDecodingValidJWT", testDecodingValidJWT),
      ("testFailsToDecodeInvalidStringWithoutThreeSegments", testFailsToDecodeInvalidStringWithoutThreeSegments),
      ("testDisablingVerify", testDisablingVerify),
      ("testSuccessfulIssuerValidation", testSuccessfulIssuerValidation),
      ("testIncorrectIssuerValidation", testIncorrectIssuerValidation),
      ("testMissingIssuerValidation", testMissingIssuerValidation),
      ("testExpiredClaim", testExpiredClaim),
      ("testInvalidExpiaryClaim", testInvalidExpiaryClaim),
      ("testUnexpiredClaim", testUnexpiredClaim),
      ("testUnexpiredClaimString", testUnexpiredClaimString),
      ("testNotBeforeClaim", testNotBeforeClaim),
      ("testNotBeforeClaimString", testNotBeforeClaimString),
      ("testInvalidNotBeforeClaim", testInvalidNotBeforeClaim),
      ("testUnmetNotBeforeClaim", testUnmetNotBeforeClaim),
      ("testIssuedAtClaimInThePast", testIssuedAtClaimInThePast),
      ("testIssuedAtClaimInThePastString", testIssuedAtClaimInThePastString),
      ("testIssuedAtClaimInTheFuture", testIssuedAtClaimInTheFuture),
      ("testInvalidIssuedAtClaim", testInvalidIssuedAtClaim),
      ("testAudiencesClaim", testAudiencesClaim),
      ("testAudienceClaim", testAudienceClaim),
      ("testMismatchAudienceClaim", testMismatchAudienceClaim),
      ("testMissingAudienceClaim", testMissingAudienceClaim),
      ("testNoneAlgorithm", testNoneAlgorithm),
      ("testNoneFailsWithSecretAlgorithm", testNoneFailsWithSecretAlgorithm),
      ("testMatchesAnyAlgorithm", testMatchesAnyAlgorithm),
      ("testHS384Algorithm", testHS384Algorithm),
      ("testHS512Algorithm", testHS512Algorithm),
    ]
  }
}

extension PayloadTests {
  static var allTests: [(String, (PayloadTests) -> (Void) throws -> Void)] {
    return [
      ("testIssuer", testIssuer),
      ("testAudience", testAudience),
      ("testExpiration", testExpiration),
      ("testNotBefore", testNotBefore),
      ("testIssuedAt", testIssuedAt),
      ("testCustomAttributes", testCustomAttributes),
    ]
  }
}

XCTMain([
  testCase(EncodeTests.allTests),
  testCase(DecodeTests.allTests),
  testCase(PayloadTests.allTests),
])
