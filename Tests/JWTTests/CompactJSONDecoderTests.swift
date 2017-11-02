import XCTest
@testable import JWT

class CompactJSONDecodable: Decodable {
  let key: String
}

class CompactJSONDecoderTests: XCTestCase {
  let decoder = CompactJSONDecoder()

  func testDecoder() throws {
    let expected = "eyJrZXkiOiJ2YWx1ZSJ9".data(using: .ascii)!
    let value = try decoder.decode(CompactJSONDecodable.self, from: expected)
    XCTAssertEqual(value.key, "value")
  }
}
