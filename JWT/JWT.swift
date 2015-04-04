import Foundation

public typealias Payload = [String:AnyObject]

public enum InvalidToken : Printable {
  case DecodeError(String)

  public var description:String {
    switch self {
      case .DecodeError(let error):
        return "Decode Error: \(error)"
    }
  }
}

public enum DecodeResult {
  case Success(Payload)
  case Failure(InvalidToken)
}


/// Decode a JWT
public func decode(jwt:String, verify:Bool = false) -> DecodeResult {
  switch load(jwt) {
    case let .Success(header, payload, signature, signatureInput):
      return .Success(payload)
    case .Failure(let failure):
      return .Failure(failure)
  }
}

// MARK: Parsing a JWT

enum LoadResult {
  case Success(header:Payload, payload:Payload, signature:NSData, signatureInput:String)
  case Failure(InvalidToken)
}

/// URL Base64 Decoding
func base64decode(input:String) -> NSData? {
  let rem = countElements(input) % 4

  var ending = ""
  if rem > 0 {
    let amount = 4 - rem
    ending = String(count: amount, repeatedValue: Character("="))
  }

  let base64 = input.stringByReplacingOccurrencesOfString("-", withString: "+", options: NSStringCompareOptions(0), range: nil)
    .stringByReplacingOccurrencesOfString("_", withString: "/", options: NSStringCompareOptions(0), range: nil) + ending

  return NSData(base64EncodedString: base64, options: NSDataBase64DecodingOptions(0))
}

func load(jwt:String) -> LoadResult {
  let segments = jwt.componentsSeparatedByString(".")
  if segments.count != 3 {
    return .Failure(.DecodeError("Not enough segments"))
  }

  let headerSegment = segments[0]
  let payloadSegment = segments[1]
  let signatureSegment = segments[2]
  let signatureInput = "\(headerSegment).\(payloadSegment)"

  let headerData = base64decode(headerSegment)
  if headerData == nil {
    return .Failure(.DecodeError("Header is not correctly encoded as base64"))
  }

  let header = NSJSONSerialization.JSONObjectWithData(headerData!, options: NSJSONReadingOptions(0), error: nil) as? Payload
  if header == nil {
    return .Failure(.DecodeError("Invalid header"))
  }

  let payloadData = base64decode(payloadSegment)
  if payloadData == nil {
    return .Failure(.DecodeError("Payload is not correctly encoded as base64"))
  }

  let payload = NSJSONSerialization.JSONObjectWithData(payloadData!, options: NSJSONReadingOptions(0), error: nil) as? Payload
  if payload == nil {
    return .Failure(.DecodeError("Invalid payload"))
  }

  let signature = base64decode(signatureSegment)
  if signature == nil {
    return .Failure(.DecodeError("Signature is not correctly encoded as base64"))
  }

  return .Success(header:header!, payload:payload!, signature:signature!, signatureInput:signatureInput)
}
