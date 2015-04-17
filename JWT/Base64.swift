import Foundation


/// URI Safe base64 encode
func base64encode(input:NSData) -> String {
  let data = input.base64EncodedDataWithOptions(NSDataBase64EncodingOptions(0))
  let string = NSString(data: data, encoding: NSUTF8StringEncoding) as! String
  return string
    .stringByReplacingOccurrencesOfString("+", withString: "-", options: NSStringCompareOptions(0), range: nil)
    .stringByReplacingOccurrencesOfString("/", withString: "_", options: NSStringCompareOptions(0), range: nil)
    .stringByReplacingOccurrencesOfString("=", withString: "", options: NSStringCompareOptions(0), range: nil)
}

/// URI Safe base64 decode
func base64decode(input:String) -> NSData? {
  let rem = count(input) % 4

  var ending = ""
  if rem > 0 {
    let amount = 4 - rem
    ending = String(count: amount, repeatedValue: Character("="))
  }

  let base64 = input.stringByReplacingOccurrencesOfString("-", withString: "+", options: NSStringCompareOptions(0), range: nil)
    .stringByReplacingOccurrencesOfString("_", withString: "/", options: NSStringCompareOptions(0), range: nil) + ending

  return NSData(base64EncodedString: base64, options: NSDataBase64DecodingOptions(0))
}
