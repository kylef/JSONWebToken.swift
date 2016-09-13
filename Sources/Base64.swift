import Foundation


/// URI Safe base64 encode
func base64encode(_ input:Data) -> String {
  let data = input.base64EncodedData(options: NSData.Base64EncodingOptions(rawValue: 0))
  let string = NSString(data: data, encoding: String.Encoding.utf8.rawValue) as! String
  return string
    .replacingOccurrences(of: "+", with: "-", options: NSString.CompareOptions(rawValue: 0), range: nil)
    .replacingOccurrences(of: "/", with: "_", options: NSString.CompareOptions(rawValue: 0), range: nil)
    .replacingOccurrences(of: "=", with: "", options: NSString.CompareOptions(rawValue: 0), range: nil)
}

/// URI Safe base64 decode
func base64decode(_ input:String) -> Data? {
  let rem = input.characters.count % 4

  var ending = ""
  if rem > 0 {
    let amount = 4 - rem
    ending = String(repeating: "=", count: amount)
  }

  let base64 = input.replacingOccurrences(of: "-", with: "+", options: NSString.CompareOptions(rawValue: 0), range: nil)
    .replacingOccurrences(of: "_", with: "/", options: NSString.CompareOptions(rawValue: 0), range: nil) + ending

  return Data(base64Encoded: base64, options: NSData.Base64DecodingOptions(rawValue: 0))
}
