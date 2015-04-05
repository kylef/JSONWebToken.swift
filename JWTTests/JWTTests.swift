import XCTest
import JWT

class JWTEncodeTests : XCTestCase {
  func testEncodingJWT() {
    let payload = ["name": "Kyle"] as Payload
    let jwt = JWT.encode(payload, .HS256("secret"))
    let fixture = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjoiS3lsZSJ9.zxm7xcp1eZtZhp4t-nlw09ATQnnFKIiSN83uG8u6cAg"
    XCTAssertEqual(jwt, fixture)
  }

  func testEncodingWithBuilder() {
    let algorithm = Algorithm.HS256("secret")
    let jwt = JWT.encode(algorithm) { builder in
      builder.issuer = "fuller.li"
    }

    assertSuccess(JWT.decode(jwt, algorithm)) { payload in
      XCTAssertEqual(payload as NSDictionary, ["iss": "fuller.li"])
    }
  }
}

class JWTPayloadBuilder : XCTestCase {
  func testIssuer() {
    JWT.encode(.None) { builder in
       builder.issuer = "fuller.li"
      XCTAssertEqual(builder.issuer!, "fuller.li")
      XCTAssertEqual(builder["iss"] as String, "fuller.li")
    }
  }

  func testAudience() {
    JWT.encode(.None) { builder in
      builder.audience = "cocoapods"
      XCTAssertEqual(builder.audience!, "cocoapods")
      XCTAssertEqual(builder["aud"] as String, "cocoapods")
    }
  }

  func testExpiration() {
    JWT.encode(.None) { builder in
      let date = NSDate(timeIntervalSince1970: NSDate().timeIntervalSince1970)
      builder.expiration = date
      XCTAssertEqual(builder.expiration!, date)
      XCTAssertEqual(builder["exp"] as NSTimeInterval, date.timeIntervalSince1970)
    }
  }

  func testNotBefore() {
    JWT.encode(.None) { builder in
      let date = NSDate(timeIntervalSince1970: NSDate().timeIntervalSince1970)
      builder.notBefore = date
      XCTAssertEqual(builder.notBefore!, date)
      XCTAssertEqual(builder["nbf"] as NSTimeInterval, date.timeIntervalSince1970)
    }
  }

  func testIssuedAt() {
    JWT.encode(.None) { builder in
      let date = NSDate(timeIntervalSince1970: NSDate().timeIntervalSince1970)
      builder.issuedAt = date
      XCTAssertEqual(builder.issuedAt!, date)
      XCTAssertEqual(builder["iat"] as NSTimeInterval, date.timeIntervalSince1970)
    }
  }

  func testCustomAttributes() {
    JWT.encode(.None) { builder in
      builder["user"] = "kyle"
      XCTAssertEqual(builder["user"] as String, "kyle")
    }
  }
}

class JWTDecodeTests : XCTestCase {
  func testDecodingValidJWT() {
    let jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjoiS3lsZSJ9.zxm7xcp1eZtZhp4t-nlw09ATQnnFKIiSN83uG8u6cAg"
    let result = JWT.decode(jwt, .HS256("secret"))
    assertSuccess(result) { payload in
      XCTAssertEqual(payload as NSDictionary, ["name": "Kyle"])
    }
  }

  func testFailsToDecodeInvalidStringWithoutThreeSegments() {
    assertDecodeError(decode("a.b", .None), "Not enough segments")
  }

  // MARK: Disable verify

  func testDisablingVerify() {
    let jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.2_8pWJfyPup0YwOXK7g9Dn0cF1E3pdn299t4hSeJy5w"
    assertSuccess(decode(jwt, .None, verify:false, issuer:"fuller.li"))
  }

  // MARK: Issuer claim

  func testSuccessfulIssuerValidation() {
    let jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJmdWxsZXIubGkifQ.d7B7PAQcz1E6oNhrlxmHxHXHgg39_k7X7wWeahl8kSQ"
    assertSuccess(decode(jwt, .HS256("secret"), issuer:"fuller.li")) { payload in
      XCTAssertEqual(payload as NSDictionary, ["iss": "fuller.li"])
    }
  }

  func testIncorrectIssuerValidation() {
    let jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJmdWxsZXIubGkifQ.wOhJ9_6lx-3JGJPmJmtFCDI3kt7uMAMmhHIslti7ryI"
    assertFailure(decode(jwt, .HS256("secret"), issuer:"querykit.org"))
  }

  func testMissingIssuerValidation() {
    let jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.2_8pWJfyPup0YwOXK7g9Dn0cF1E3pdn299t4hSeJy5w"
    assertFailure(decode(jwt, .HS256("secret"), issuer:"fuller.li"))
  }

  // MARK: Expiration claim

  func testExpiredClaim() {
    let jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE0MjgxODg0OTF9.cy6b2szsNkKnHFnz2GjTatGjoHBTs8vBKnPGZgpp91I"
    assertFailure(decode(jwt, .HS256("secret")))
  }

  func testInvalidExpiaryClaim() {
    let jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOlsiMTQyODE4ODQ5MSJdfQ.OwF-wd3THjxrEGUhh6IdnNhxQZ7ydwJ3Z6J_dfl9MBs"
    assertFailure(decode(jwt, .HS256("secret")))
  }

  func testUnexpiredClaim() {
    // If this just started failing, hello 2024!
    let jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3MjgxODg0OTF9.EW7k-8Mvnv0GpvOKJalFRLoCB3a3xGG3i7hAZZXNAz0"
    assertSuccess(decode(jwt, .HS256("secret"))) { payload in
      XCTAssertEqual(payload as NSDictionary, ["exp": 1728188491])
    }
  }

  // MARK: Not before claim

  func testNotBeforeClaim() {
    let jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYmYiOjE0MjgxODk3MjB9.jFT0nXAJvEwyG6R7CMJlzNJb7FtZGv30QRZpYam5cvs"
    assertSuccess(decode(jwt, .HS256("secret"))) { payload in
      XCTAssertEqual(payload as NSDictionary, ["nbf": 1428189720])
    }
  }

  func testInvalidNotBeforeClaim() {
    let jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYmYiOlsxNDI4MTg5NzIwXX0.PUL1FQubzzJa4MNXe2D3d5t5cMaqFr3kYlzRUzly-C8"
    assertDecodeError(decode(jwt, .HS256("secret")), "Not before claim (nbf) must be an integer")
  }

  func testUnmetNotBeforeClaim() {
    // If this just started failing, hello 2024!
    let jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYmYiOjE3MjgxODg0OTF9.Tzhu1tu-7BXcF5YEIFFE1Vmg4tEybUnaz58FR4PcblQ"
    assertFailure(decode(jwt, .HS256("secret")))
  }

  // MARK: Issued at claim

  func testIssuedAtClaimInThePast() {
    let jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpYXQiOjE0MjgxODk3MjB9.I_5qjRcCUZVQdABLwG82CSuu2relSdIyJOyvXWUAJh4"
    assertSuccess(decode(jwt, .HS256("secret"))) { payload in
      XCTAssertEqual(payload as NSDictionary, ["iat": 1428189720])
    }
  }

  func testIssuedAtClaimInTheFuture() {
    // If this just started failing, hello 2024!
    let jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpYXQiOjE3MjgxODg0OTF9.owHiJyJmTcW1lBW5y_Rz3iBfSbcNiXlbZ2fY9qR7-aU"
    assertFailure(decode(jwt, .HS256("secret")))
  }

  func testInvalidIssuedAtClaim() {
    // If this just started failing, hello 2024!
    let jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpYXQiOlsxNzI4MTg4NDkxXX0.ND7QMWtLkXDXH38OaXM3SQgLo3Z5TNgF_pcfWHV_alQ"
    assertDecodeError(decode(jwt, .HS256("secret")), "Issued at claim (iat) must be an integer")
  }

  // MARK: Audience claims

  func testAudiencesClaim() {
    let jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOlsibWF4aW5lIiwia2F0aWUiXX0.-PKvdNLCClrWG7CvesHP6PB0-vxu-_IZcsYhJxBy5JM"
    assertSuccess(decode(jwt, .HS256("secret"), audience:"maxine")) { payload in
      XCTAssertEqual(payload as NSDictionary, ["aud": ["maxine", "katie"]])
    }
  }

  func testAudienceClaim() {
    let jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJreWxlIn0.dpgH4JOwueReaBoanLSxsGTc7AjKUvo7_M1sAfy_xVE"
    assertSuccess(decode(jwt, .HS256("secret"), audience:"kyle")) { payload in
      XCTAssertEqual(payload as NSDictionary, ["aud": "kyle"])
    }
  }

  func testMismatchAudienceClaim() {
    let jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJreWxlIn0.VEB_n06pTSLlTXPFkc46ARADJ9HXNUBUPo3VhL9RDe4" // kyle
    assertFailure(decode(jwt, .HS256("secret"), audience:"maxine"))
  }

  func testMissingAudienceClaim() {
    let jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.2_8pWJfyPup0YwOXK7g9Dn0cF1E3pdn299t4hSeJy5w"
    assertFailure(decode(jwt, .HS256("secret"), audience:"kyle"))
  }

  // MARK: Signature verification

  func testNoneAlgorithm() {
    let jwt = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ0ZXN0IjoiaW5nIn0."
    assertSuccess(decode(jwt, .None)) { payload in
      XCTAssertEqual(payload as NSDictionary, ["test": "ing"])
    }
  }

  func testNoneFailsWithSecretAlgorithm() {
    let jwt = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ0ZXN0IjoiaW5nIn0."
    assertFailure(decode(jwt, .HS256("secret")))
  }

  func testMatchesAnyAlgorithm() {
    let jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.2_8pWJfyPup0YwOXK7g9Dn0cF1E3pdn299t4hSeJy5w."
    assertFailure(decode(jwt, [.HS256("anothersecret"), .HS256("secret")]))

  func testHS384Algorithm() {
    let jwt = "eyJhbGciOiJIUzM4NCIsInR5cCI6IkpXVCJ9.eyJzb21lIjoicGF5bG9hZCJ9.lddiriKLoo42qXduMhCTKZ5Lo3njXxOC92uXyvbLyYKzbq4CVVQOb3MpDwnI19u4"
    assertSuccess(decode(jwt, .HS384("secret"))) { payload in
      XCTAssertEqual(payload as NSDictionary, ["some": "payload"])
    }
  }

  func testHS512Algorithm() {
    let jwt = "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJzb21lIjoicGF5bG9hZCJ9.WTzLzFO079PduJiFIyzrOah54YaM8qoxH9fLMQoQhKtw3_fMGjImIOokijDkXVbyfBqhMo2GCNu4w9v7UXvnpA"
    assertSuccess(decode(jwt, .HS512("secret"))) { payload in
      XCTAssertEqual(payload as NSDictionary, ["some": "payload"])
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
      XCTFail("Failure for the wrong reason \(failure)")
    }
  }
}
