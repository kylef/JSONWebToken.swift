class CompactJSONDecoder: JSONDecoder {
  override func decode<T>(_ type: T.Type, from data: Data) throws -> T where T : Decodable {
    guard let string = String(data: data, encoding: .ascii) else {
      fatalError()
    }

    return try super.decode(type, from: base64decode(string)!)
  }
}
