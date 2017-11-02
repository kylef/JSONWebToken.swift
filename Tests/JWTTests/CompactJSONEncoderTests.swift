import XCTest
@testable import JWT

class CompactJSONEncodable: Encodable {
  let key: String

  init(key: String) {
    self.key = key
  }
}

class CompactJSONEncoderTests: XCTestCase {
  let encoder = CompactJSONEncoder()

  func testEncode() throws {
    let value = CompactJSONEncodable(key: "value")

    let encoded = try encoder.encode(value)

    XCTAssertEqual(encoded, "eyJrZXkiOiJ2YWx1ZSJ9".data(using: .ascii)!)
  }
}

