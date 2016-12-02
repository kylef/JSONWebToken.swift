import Foundation

func validateDate(_ payload: Payload, key: String, comparison: ComparisonResult, failure: InvalidToken, decodeError: String) throws {
  if payload[key] == nil {
    return
  }

  guard let date = extractDate(payload: payload, key: key) else {
    throw InvalidToken.decodeError(decodeError)
  }

  if date.compare(Date()) == comparison {
    throw failure
  }
}

fileprivate func extractDate(payload: Payload, key: String) -> Date? {
  if let timestamp = payload[key] as? TimeInterval {
    return Date(timeIntervalSince1970: timestamp)
  }

  if let timestamp = payload[key] as? Int {
    return Date(timeIntervalSince1970: Double(timestamp))
  }

  if let timestampString = payload[key] as? String, let timestamp = Double(timestampString) {
    return Date(timeIntervalSince1970: timestamp)
  }

  return nil
}
