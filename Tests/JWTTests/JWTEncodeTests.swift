import XCTest
import JWT


class JWTEncodeTests: XCTestCase {
  func testEncodingJWT() {
    let payload = ["name": "Kyle"] as Payload
    let jwt = JWT.encode(claims: payload, algorithm: .hs256("secret".data(using: .utf8)!))

    let expected = [
      // { "alg": "HS256", "typ": "JWT" }
      "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjoiS3lsZSJ9.zxm7xcp1eZtZhp4t-nlw09ATQnnFKIiSN83uG8u6cAg",

      // {  "typ": "JWT", "alg": "HS256" }
      "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJuYW1lIjoiS3lsZSJ9.4tCpoxfyfjbUyLjm9_zu-r52Vxn6bFq9kp6Rt9xMs4A",
    ]

    XCTAssertTrue(expected.contains(jwt))
  }

  func testEncodingWithBuilder() {
    let algorithm = Algorithm.hs256("secret".data(using: .utf8)!)
    let jwt = JWT.encode(algorithm) { builder in
      builder.issuer = "fuller.li"
    }

    XCTAssertEqual(jwt, "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJmdWxsZXIubGkifQ.d7B7PAQcz1E6oNhrlxmHxHXHgg39_k7X7wWeahl8kSQ")
  }

  func testEncodingClaimsWithHeaders() {
    let algorithm = Algorithm.hs256("secret".data(using: .utf8)!)
    let jwt = JWT.encode(claims: ClaimSet(), algorithm: algorithm, headers: ["kid": "x"])

    XCTAssertEqual(jwt, "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IngifQ.e30.ddEotxYYMMdat5HPgYFQnkHRdPXsxPG71ooyhIUoqGA")
  }
}
