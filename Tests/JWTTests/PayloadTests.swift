import XCTest
import JWT

class PayloadTests: XCTestCase {
  func testIssuer() {
    _ = JWT.encode(.none) { builder in
      builder.issuer = "fuller.li"
      XCTAssertEqual(builder.issuer, "fuller.li")
      XCTAssertEqual(builder["iss"] as? String, "fuller.li")
    }
  }

  func testAudience() {
    _ = JWT.encode(.none) { builder in
      builder.audience = "cocoapods"
      XCTAssertEqual(builder.audience, "cocoapods")
      XCTAssertEqual(builder["aud"] as? String, "cocoapods")
    }
  }

  func testExpiration() {
    _ = JWT.encode(.none) { builder in
      let date = Date(timeIntervalSince1970: Date().timeIntervalSince1970)
      builder.expiration = date
      XCTAssertEqual(builder.expiration, date)
      XCTAssertEqual(builder["exp"] as? TimeInterval, date.timeIntervalSince1970)
    }
  }

  func testNotBefore() {
    _ = JWT.encode(.none) { builder in
      let date = Date(timeIntervalSince1970: Date().timeIntervalSince1970)
      builder.notBefore = date
      XCTAssertEqual(builder.notBefore, date)
      XCTAssertEqual(builder["nbf"] as? TimeInterval, date.timeIntervalSince1970)
    }
  }

  func testIssuedAt() {
    _ = JWT.encode(.none) { builder in
      let date = Date(timeIntervalSince1970: Date().timeIntervalSince1970)
      builder.issuedAt = date
      XCTAssertEqual(builder.issuedAt, date)
      XCTAssertEqual(builder["iat"] as? TimeInterval, date.timeIntervalSince1970)
    }
  }

  func testCustomAttributes() {
    _ = JWT.encode(.none) { builder in
      builder["user"] = "kyle"
      XCTAssertEqual(builder["user"] as? String, "kyle")
    }
  }
}
