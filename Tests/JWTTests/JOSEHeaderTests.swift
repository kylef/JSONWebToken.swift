import XCTest
@testable import JWT

class JOSEHeaderTests: XCTestCase {
  // MARK: Algorithm

  func testGettingUnsetAlgoritm() {
    let header = JOSEHeader(parameters: [:])
    XCTAssertNil(header.algorithm)
  }

  func testGettingAlgoritm() {
    let header = JOSEHeader(parameters: ["alg": "none"])
    XCTAssertEqual(header.algorithm, "none")
  }

  func testSettingAlgoritm() {
    var header = JOSEHeader(parameters: [:])

    header.algorithm = "none"
    XCTAssertEqual(header.algorithm, "none")
  }

  // MARK: Type

  func testGettingUnsetType() {
    let header = JOSEHeader(parameters: [:])
    XCTAssertNil(header.type)
  }

  func testGettingType() {
    let header = JOSEHeader(parameters: ["typ": "JWT"])
    XCTAssertEqual(header.type, "JWT")
  }

  func testSettingType() {
    var header = JOSEHeader(parameters: [:])

    header.type = "JWT"
    XCTAssertEqual(header.type, "JWT")
  }
}
