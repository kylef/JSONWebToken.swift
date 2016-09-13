import Foundation
import XCTest
import JWT

class JWTEncodeTests : XCTestCase {
  func testEncodingJWT() {
    let payload = ["name": "Kyle"] as Payload
    let jwt = JWT.encode(payload, algorithm: .hs256("secret".data(using: .utf8)!))
    let fixture = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjoiS3lsZSJ9.zxm7xcp1eZtZhp4t-nlw09ATQnnFKIiSN83uG8u6cAg"
    XCTAssertEqual(jwt, fixture)
  }

  func testEncodingWithBuilder() {
    let algorithm = Algorithm.hs256("secret".data(using: .utf8)!)
    let jwt = JWT.encode(algorithm) { builder in
      builder.issuer = "fuller.li"
    }

    assertSuccess(try JWT.decode(jwt, algorithm: algorithm)) { payload in
      XCTAssertEqual(payload as NSDictionary, ["iss": "fuller.li"])
    }
  }
}

class JWTPayloadBuilder : XCTestCase {
  func testIssuer() {
    JWT.encode(.none) { builder in
       builder.issuer = "fuller.li"
      XCTAssertEqual(builder.issuer, "fuller.li")
      XCTAssertEqual(builder["iss"] as? String, "fuller.li")
    }
  }

  func testAudience() {
    JWT.encode(.none) { builder in
      builder.audience = "cocoapods"
      XCTAssertEqual(builder.audience, "cocoapods")
      XCTAssertEqual(builder["aud"] as? String, "cocoapods")
    }
  }

  func testExpiration() {
    JWT.encode(.none) { builder in
      let date = Date(timeIntervalSince1970: Date().timeIntervalSince1970)
      builder.expiration = date
      XCTAssertEqual(builder.expiration, date)
      XCTAssertEqual(builder["exp"] as? TimeInterval, date.timeIntervalSince1970)
    }
  }

  func testNotBefore() {
    JWT.encode(.none) { builder in
      let date = Date(timeIntervalSince1970: Date().timeIntervalSince1970)
      builder.notBefore = date
      XCTAssertEqual(builder.notBefore, date)
      XCTAssertEqual(builder["nbf"] as? TimeInterval, date.timeIntervalSince1970)
    }
  }

  func testIssuedAt() {
    JWT.encode(.none) { builder in
      let date = Date(timeIntervalSince1970: Date().timeIntervalSince1970)
      builder.issuedAt = date
      XCTAssertEqual(builder.issuedAt, date)
      XCTAssertEqual(builder["iat"] as? TimeInterval, date.timeIntervalSince1970)
    }
  }

  func testCustomAttributes() {
    JWT.encode(.none) { builder in
      builder["user"] = "kyle"
      XCTAssertEqual(builder["user"] as? String, "kyle")
    }
  }
}

class JWTDecodeTests : XCTestCase {
  func testDecodingValidJWT() {
    let jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjoiS3lsZSJ9.zxm7xcp1eZtZhp4t-nlw09ATQnnFKIiSN83uG8u6cAg"

    assertSuccess(try JWT.decode(jwt, algorithm: .hs256("secret".data(using: .utf8)!))) { payload in
      XCTAssertEqual(payload as NSDictionary, ["name": "Kyle"])
    }
  }

  func testFailsToDecodeInvalidStringWithoutThreeSegments() {
    assertDecodeError(try decode("a.b", algorithm: .none), error: "Not enough segments")
  }

  // MARK: Disable verify

  func testDisablingVerify() {
    let jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.2_8pWJfyPup0YwOXK7g9Dn0cF1E3pdn299t4hSeJy5w"
    assertSuccess(try decode(jwt, algorithm: .none, verify:false, issuer:"fuller.li"))
  }

  // MARK: Issuer claim

  func testSuccessfulIssuerValidation() {
    let jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJmdWxsZXIubGkifQ.d7B7PAQcz1E6oNhrlxmHxHXHgg39_k7X7wWeahl8kSQ"
    assertSuccess(try decode(jwt, algorithm: .hs256("secret".data(using: .utf8)!), issuer:"fuller.li")) { payload in
      XCTAssertEqual(payload as NSDictionary, ["iss": "fuller.li"])
    }
  }

  func testIncorrectIssuerValidation() {
    let jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJmdWxsZXIubGkifQ.wOhJ9_6lx-3JGJPmJmtFCDI3kt7uMAMmhHIslti7ryI"
    assertFailure(try decode(jwt, algorithm: .hs256("secret".data(using: .utf8)!), issuer:"querykit.org"))
  }

  func testMissingIssuerValidation() {
    let jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.2_8pWJfyPup0YwOXK7g9Dn0cF1E3pdn299t4hSeJy5w"
    assertFailure(try decode(jwt, algorithm: .hs256("secret".data(using: .utf8)!), issuer:"fuller.li"))
  }

  // MARK: Expiration claim

  func testExpiredClaim() {
    let jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE0MjgxODg0OTF9.cy6b2szsNkKnHFnz2GjTatGjoHBTs8vBKnPGZgpp91I"
    assertFailure(try decode(jwt, algorithm: .hs256("secret".data(using: .utf8)!)))
  }

  func testInvalidExpiaryClaim() {
    let jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOlsiMTQyODE4ODQ5MSJdfQ.OwF-wd3THjxrEGUhh6IdnNhxQZ7ydwJ3Z6J_dfl9MBs"
    assertFailure(try decode(jwt, algorithm: .hs256("secret".data(using: .utf8)!)))
  }

  func testUnexpiredClaim() {
    // If this just started failing, hello 2024!
    let jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3MjgxODg0OTF9.EW7k-8Mvnv0GpvOKJalFRLoCB3a3xGG3i7hAZZXNAz0"
    assertSuccess(try decode(jwt, algorithm: .hs256("secret".data(using: .utf8)!))) { payload in
      XCTAssertEqual(payload as NSDictionary, ["exp": 1728188491])
    }
  }
  
  func testUnexpiredClaimString() {
    // If this just started failing, hello 2024!
    let jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOiIxNzI4MTg4NDkxIn0.y4w7lNLrfRRPzuNUfM-ZvPkoOtrTU_d8ZVYasLdZGpk"
    assertSuccess(try decode(jwt, algorithm: .hs256("secret".data(using: .utf8)!))) { payload in
      XCTAssertEqual(payload as NSDictionary, ["exp": "1728188491"])
    }
  }

  // MARK: Not before claim

  func testNotBeforeClaim() {
    let jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYmYiOjE0MjgxODk3MjB9.jFT0nXAJvEwyG6R7CMJlzNJb7FtZGv30QRZpYam5cvs"
    assertSuccess(try decode(jwt, algorithm: .hs256("secret".data(using: .utf8)!))) { payload in
      XCTAssertEqual(payload as NSDictionary, ["nbf": 1428189720])
    }
  }
  
  func testNotBeforeClaimString() {
    let jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYmYiOiIxNDI4MTg5NzIwIn0.qZsj36irdmIAeXv6YazWDSFbpuxHtEh4Deof5YTpnVI"
    assertSuccess(try decode(jwt, algorithm: .hs256("secret".data(using: .utf8)!))) { payload in
      XCTAssertEqual(payload as NSDictionary, ["nbf": "1428189720"])
    }
  }

  func testInvalidNotBeforeClaim() {
    let jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYmYiOlsxNDI4MTg5NzIwXX0.PUL1FQubzzJa4MNXe2D3d5t5cMaqFr3kYlzRUzly-C8"
    assertDecodeError(try decode(jwt, algorithm: .hs256("secret".data(using: .utf8)!)), error: "Not before claim (nbf) must be an integer")
  }

  func testUnmetNotBeforeClaim() {
    // If this just started failing, hello 2024!
    let jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYmYiOjE3MjgxODg0OTF9.Tzhu1tu-7BXcF5YEIFFE1Vmg4tEybUnaz58FR4PcblQ"
    assertFailure(try decode(jwt, algorithm: .hs256("secret".data(using: .utf8)!)))
  }

  // MARK: Issued at claim

  func testIssuedAtClaimInThePast() {
    let jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpYXQiOjE0MjgxODk3MjB9.I_5qjRcCUZVQdABLwG82CSuu2relSdIyJOyvXWUAJh4"
    assertSuccess(try decode(jwt, algorithm: .hs256("secret".data(using: .utf8)!))) { payload in
      XCTAssertEqual(payload as NSDictionary, ["iat": 1428189720])
    }
  }
  
  func testIssuedAtClaimInThePastString() {
    let jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpYXQiOiIxNDI4MTg5NzIwIn0.M8veWtsY52oBwi7LRKzvNnzhjK0QBS8Su1r0atlns2k"
    assertSuccess(try decode(jwt, algorithm: .hs256("secret".data(using: .utf8)!))) { payload in
      XCTAssertEqual(payload as NSDictionary, ["iat": "1428189720"])
    }
  }

  func testIssuedAtClaimInTheFuture() {
    // If this just started failing, hello 2024!
    let jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpYXQiOjE3MjgxODg0OTF9.owHiJyJmTcW1lBW5y_Rz3iBfSbcNiXlbZ2fY9qR7-aU"
    assertFailure(try decode(jwt, algorithm: .hs256("secret".data(using: .utf8)!)))
  }

  func testInvalidIssuedAtClaim() {
    // If this just started failing, hello 2024!
    let jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpYXQiOlsxNzI4MTg4NDkxXX0.ND7QMWtLkXDXH38OaXM3SQgLo3Z5TNgF_pcfWHV_alQ"
    assertDecodeError(try decode(jwt, algorithm: .hs256("secret".data(using: .utf8)!)), error: "Issued at claim (iat) must be an integer")
  }

  // MARK: Audience claims

  func testAudiencesClaim() {
    let jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOlsibWF4aW5lIiwia2F0aWUiXX0.-PKvdNLCClrWG7CvesHP6PB0-vxu-_IZcsYhJxBy5JM"
    assertSuccess(try decode(jwt, algorithm: .hs256("secret".data(using: .utf8)!), audience:"maxine")) { payload in
      XCTAssertEqual(payload as NSDictionary, ["aud": ["maxine", "katie"]])
    }
  }

  func testAudienceClaim() {
    let jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJreWxlIn0.dpgH4JOwueReaBoanLSxsGTc7AjKUvo7_M1sAfy_xVE"
    assertSuccess(try decode(jwt, algorithm: .hs256("secret".data(using: .utf8)!), audience:"kyle")) { payload in
      XCTAssertEqual(payload as NSDictionary, ["aud": "kyle"])
    }
  }

  func testMismatchAudienceClaim() {
    let jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJreWxlIn0.VEB_n06pTSLlTXPFkc46ARADJ9HXNUBUPo3VhL9RDe4" // kyle
    assertFailure(try decode(jwt, algorithm: .hs256("secret".data(using: .utf8)!), audience:"maxine"))
  }

  func testMissingAudienceClaim() {
    let jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.2_8pWJfyPup0YwOXK7g9Dn0cF1E3pdn299t4hSeJy5w"
    assertFailure(try decode(jwt, algorithm: .hs256("secret".data(using: .utf8)!), audience:"kyle"))
  }

  // MARK: Signature verification

  func testNoneAlgorithm() {
    let jwt = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ0ZXN0IjoiaW5nIn0."
    assertSuccess(try decode(jwt, algorithm:.none)) { payload in
      XCTAssertEqual(payload as NSDictionary, ["test": "ing"])
    }
  }

  func testNoneFailsWithSecretAlgorithm() {
    let jwt = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ0ZXN0IjoiaW5nIn0."
    assertFailure(try decode(jwt, algorithm: .hs256("secret".data(using: .utf8)!)))
  }

  func testMatchesAnyAlgorithm() {
    let jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.2_8pWJfyPup0YwOXK7g9Dn0cF1E3pdn299t4hSeJy5w."
    assertFailure(try decode(jwt, algorithms: [.hs256("anothersecret".data(using: .utf8)!), .hs256("secret".data(using: .utf8)!)]))
  }

  func testHS384Algorithm() {
    let jwt = "eyJhbGciOiJIUzM4NCIsInR5cCI6IkpXVCJ9.eyJzb21lIjoicGF5bG9hZCJ9.lddiriKLoo42qXduMhCTKZ5Lo3njXxOC92uXyvbLyYKzbq4CVVQOb3MpDwnI19u4"
    assertSuccess(try decode(jwt, algorithm: .hs384("secret".data(using: .utf8)!))) { payload in
      XCTAssertEqual(payload as NSDictionary, ["some": "payload"])
    }
  }

  func testHS512Algorithm() {
    let jwt = "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJzb21lIjoicGF5bG9hZCJ9.WTzLzFO079PduJiFIyzrOah54YaM8qoxH9fLMQoQhKtw3_fMGjImIOokijDkXVbyfBqhMo2GCNu4w9v7UXvnpA"
    assertSuccess(try decode(jwt, algorithm: .hs512("secret".data(using: .utf8)!))) { payload in
      XCTAssertEqual(payload as NSDictionary, ["some": "payload"])
    }
  }
}

// MARK: Helpers

func assertSuccess(_ decoder: @autoclosure () throws -> Payload, closure:((Payload) -> ())? = nil) {
  do {
    let payload = try decoder()
    closure?(payload)
  } catch {
    XCTFail("Failed to decode while expecting success. \(error)")
  }
}

func assertFailure(_ decoder: @autoclosure () throws -> Payload, closure:((InvalidToken) -> ())? = nil) {
  do {
    _ = try decoder()
    XCTFail("Decoding succeeded, expected a failure.")
  } catch let error as InvalidToken {
    closure?(error)
  } catch {
    XCTFail("Unexpected error")
  }
}

func assertDecodeError(_ decoder:@autoclosure () throws -> Payload, error:String) {
  assertFailure(try decoder()) { failure in
    switch failure {
    case .decodeError(let decodeError):
      if decodeError != error {
        XCTFail("Incorrect decode error \(decodeError) != \(error)")
      }
    default:
      XCTFail("Failure for the wrong reason \(failure)")
    }
  }
}
