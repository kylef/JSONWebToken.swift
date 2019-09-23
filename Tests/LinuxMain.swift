import XCTest
@testable import JWATests
@testable import JWTTests

extension HMACAlgorithmTests {
  static var allTests: [(String, (HMACAlgorithmTests) -> () throws -> Void)] {
    return [
      ("testSHA256Name", testSHA256Name),
	  ("testSHA384Name", testSHA384Name),
	  ("testSHA512Name", testSHA512Name),
	  ("testSHA256Sign", testSHA256Sign),
	  ("testSHA384Sign", testSHA384Sign),
	  ("testSHA512Sign", testSHA512Sign),
	  ("testSHA256Verify", testSHA256Verify),
	  ("testSHA384Verify", testSHA384Verify),
	  ("testSHA512Verify", testSHA512Verify)
    ]
  }
}

extension NoneAlgorithmTests {
  static var allTests: [(String, (NoneAlgorithmTests) -> () throws -> Void)] {
    return [
      ("testName", testName),
      ("testSign", testSign),
      ("testVerify", testVerify)
    ]
  }
}

extension CompactJSONDecoderTests {
	static var allTests: [(String, (CompactJSONDecoderTests) -> () throws -> Void)] {
		return [
			("testDecoder", testDecoder)
		]
	}
}

extension CompactJSONEncoderTests {
	static var allTests: [(String, (CompactJSONEncoderTests) -> () throws -> Void)] {
		return [
			("testEncode", testEncode)
		]
	}
}

extension DecodeTests {
  static var allTests: [(String, (DecodeTests) -> () throws -> Void)] {
    return [
      ("testDecodingValidJWT", testDecodingValidJWT),
      ("testFailsToDecodeInvalidStringWithoutThreeSegments", testFailsToDecodeInvalidStringWithoutThreeSegments),
      ("testDisablingVerify", testDisablingVerify),
      ("testSuccessfulIssuerValidation", testSuccessfulIssuerValidation),
      ("testIncorrectIssuerValidation", testIncorrectIssuerValidation),
      ("testMissingIssuerValidation", testMissingIssuerValidation),
      ("testExpiredClaim", testExpiredClaim),
      ("testInvalidExpiryClaim", testInvalidExpiryClaim),
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
      ("testHS512Algorithm", testHS512Algorithm)
    ]
  }
}

extension IntegrationTests {
	static var allTests: [(String, (IntegrationTests) -> () throws -> Void)] {
		return [
			("testVerificationFailureWithoutLeeway", testVerificationFailureWithoutLeeway),
			("testVerificationSuccessWithLeeway", testVerificationSuccessWithLeeway)
		]
	}
}

extension JWTEncodeTests {
	static var allTests: [(String, (JWTEncodeTests) -> () throws -> Void)] {
		return [
			("testEncodingJWT", testEncodingJWT),
			("testEncodingWithBuilder", testEncodingWithBuilder),
			("testEncodingClaimsWithHeaders", testEncodingClaimsWithHeaders)
		]
	}
}

extension PayloadTests {
  static var allTests: [(String, (PayloadTests) -> () throws -> Void)] {
    return [
      ("testIssuer", testIssuer),
      ("testAudience", testAudience),
      ("testExpiration", testExpiration),
      ("testNotBefore", testNotBefore),
      ("testIssuedAt", testIssuedAt),
      ("testCustomAttributes", testCustomAttributes)
    ]
  }
}

extension ValidationTests {
	static var allTests: [(String, (ValidationTests) -> () throws -> Void)] {
		return [
			("testClaimJustExpiredWithoutLeeway", testClaimJustExpiredWithoutLeeway),
			("testClaimJustNotExpiredWithoutLeeway", testClaimJustNotExpiredWithoutLeeway),
			("testNotBeforeIsImmatureSignatureWithoutLeeway", testNotBeforeIsImmatureSignatureWithoutLeeway),
			("testNotBeforeIsValidWithLeeway", testNotBeforeIsValidWithLeeway),
			("testIssuedAtIsInFutureWithoutLeeway", testIssuedAtIsInFutureWithoutLeeway),
			("testIssuedAtIsValidWithLeeway", testIssuedAtIsValidWithLeeway)
		]
	}
}

XCTMain([
  testCase(HMACAlgorithmTests.allTests),
  testCase(NoneAlgorithmTests.allTests),
  testCase(CompactJSONDecoderTests.allTests),
  testCase(CompactJSONEncoderTests.allTests),
  testCase(DecodeTests.allTests),
  testCase(IntegrationTests.allTests),
  testCase(JWTEncodeTests.allTests),
  testCase(PayloadTests.allTests),
  testCase(ValidationTests.allTests)
])
