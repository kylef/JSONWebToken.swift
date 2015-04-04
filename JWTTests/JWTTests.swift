import XCTest
import JWT

class JWTDecodeTests : XCTestCase {
  func testDecodingValidJWT() {
    let jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjoiS3lsZSJ9.JdWehmn045QcErlAGWWU4pjq4ry1S0J0F2cAgmP3EI8"
    assertSuccess(decode(jwt)) { payload in
      XCTAssertEqual(payload as NSDictionary, ["name": "Kyle"])
    }
  }

  func testFailsToDecodeInvalidStringWithoutThreeSegments() {
    assertDecodeError(decode("a.b"), "Not enough segments")
  }

  // MARK: Disable verify

  func testDisablingVerify() {
    let jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.2_8pWJfyPup0YwOXK7g9Dn0cF1E3pdn299t4hSeJy5w"
    assertSuccess(decode(jwt, verify:false, issuer:"fuller.li"))
  }

  // MARK: Issuer claim

  func testSuccessfulIssuerValidation() {
    let jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJmdWxsZXIubGkifQ.wOhJ9_6lx-3JGJPmJmtFCDI3kt7uMAMmhHIslti7ryI"
    assertSuccess(decode(jwt, issuer:"fuller.li")) { payload in
      XCTAssertEqual(payload as NSDictionary, ["iss": "fuller.li"])
    }
  }

  func testIncorrectIssuerValidation() {
    let jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJmdWxsZXIubGkifQ.wOhJ9_6lx-3JGJPmJmtFCDI3kt7uMAMmhHIslti7ryI"
    assertFailure(decode(jwt, issuer:"querykit.org"))
  }

  func testMissingIssuerValidation() {
    let jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.2_8pWJfyPup0YwOXK7g9Dn0cF1E3pdn299t4hSeJy5w"
    assertFailure(decode(jwt, issuer:"fuller.li"))
  }

  // MARK: Expiration claim

  func testExpiredClaim() {
    let jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE0MjgxODg0OTF9.cy6b2szsNkKnHFnz2GjTatGjoHBTs8vBKnPGZgpp91I"
    assertFailure(decode(jwt))
  }

  func testInvalidExpiaryClaim() {
    let jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOlsiMTQyODE4ODQ5MSJdfQ.OwF-wd3THjxrEGUhh6IdnNhxQZ7ydwJ3Z6J_dfl9MBs"
    assertFailure(decode(jwt))
  }

  func testUnexpiredClaim() {
    // If this just started failing, hello 2024!
    let jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3MjgxODg0OTF9.7QIdg6ijLJpeiG4m_TqIG9alXLhHMidWDBELkhtUqYw"
    assertSuccess(decode(jwt)) { payload in
      XCTAssertEqual(payload as NSDictionary, ["exp": 1728188491])
    }
  }
}

// MARK: Helpers

func assertSuccess(result:DecodeResult, closure:(Payload -> ())? = nil) {
  switch result {
  case .Success(let payload):
    if let closure = closure {
      closure(payload)
    }
  case .Failure(let failure):
    XCTFail("Failed to decode while expecting success. \(failure)")
    break
  }
}

func assertFailure(result:DecodeResult, closure:(InvalidToken -> ())? = nil) {
  switch result {
  case .Success(let payload):
    XCTFail("Decoded when expecting a failure.")
  case .Failure(let failure):
    if let closure = closure {
      closure(failure)
    }
    break
  }
}

func assertDecodeError(result:DecodeResult, error:String) {
  assertFailure(result) { failure in
    switch failure {
    case .DecodeError(let decodeError):
      if decodeError != error {
        XCTFail("Incorrect decode error \(decodeError) != \(error)")
      }
    default:
      XCTFail("Failure for the wrong reason")
    }
  }
}
