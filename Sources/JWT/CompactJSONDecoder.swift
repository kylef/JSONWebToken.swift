class CompactJSONDecoder: JSONDecoder {
  override func decode<T>(_ type: T.Type, from data: Data) throws -> T where T : Decodable {
    guard let string = String(data: data, encoding: .ascii) else {
      throw InvalidToken.decodeError("data should contain only ASCII characters")
    }

    return try decode(type, from: string)
  }

  func decode<T>(_ type: T.Type, from string: String) throws -> T where T : Decodable {
    guard let decoded = base64decode(string) else {
      throw InvalidToken.decodeError("data should be a valid base64 string")
    }

    return try super.decode(type, from: decoded)
  }
}
