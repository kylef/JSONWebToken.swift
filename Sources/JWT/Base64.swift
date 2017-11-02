import Foundation

/// URI Safe base64 encode
func base64encode(_ input: Data) -> String {
  let data = input.base64EncodedData()
  let string = String(data: data, encoding: .utf8)!
  return string
    .replacingOccurrences(of: "+", with: "-")
    .replacingOccurrences(of: "/", with: "_")
    .replacingOccurrences(of: "=", with: "")
}

/// URI Safe base64 decode
func base64decode(_ input: String) -> Data? {
  let rem = input.count % 4

  var ending = ""
  if rem > 0 {
    let amount = 4 - rem
    ending = String(repeating: "=", count: amount)
  }

  let base64 = input.replacingOccurrences(of: "-", with: "+")
    .replacingOccurrences(of: "_", with: "/") + ending

  return Data(base64Encoded: base64)
}
