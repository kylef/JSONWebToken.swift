import XCTest
import JWA


class NoneAlgorithmTests: XCTestCase {
  let message = "message".data(using: .utf8)!
  let signature = Data()

  func testName() {
    let algorithm = NoneAlgorithm()
    XCTAssertEqual(algorithm.name, "none")
  }

  func testSign() {
    let algorithm = NoneAlgorithm()
    XCTAssertEqual(algorithm.sign(message), signature)
  }

  func testVerify() {
    let algorithm = NoneAlgorithm()
    XCTAssertTrue(algorithm.verify(message, signature: signature))
  }
}
