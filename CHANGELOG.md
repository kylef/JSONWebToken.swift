# JSON Web Token Changelog

## 2.0.1

This release adds support for Swift 3.0.

### Breaking

- Algorithms now take `Data` instead of a `String`. This improves the API
  allowing you to use keys that cannot be serialised as a String.

  You can easily convert a String to Data such as in the following example:

  ```swift
  .hs256("secret".data(using: .utf8)!)
  ```


## 1.5.0

This release updates the dependency on CryptoSwift to ~> 0.4.0 which adds
support for Swift 2.2.
