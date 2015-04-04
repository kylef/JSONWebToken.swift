# JSON Web Token

[![Build Status](http://img.shields.io/travis/kylef/JWT.swift/master.svg?style=flat)](https://travis-ci.org/kylef/JWT.swift)

Swift implementation of [JSON Web Token](https://tools.ietf.org/html/draft-ietf-oauth-json-web-token-32).

## Installation

[CocoaPods](http://cocoapods.org/) is the recommended installation method.

```ruby
pod 'JWT'
```

## Usage

### Decoding a JWT

```swift
import JWT

JWT.decode("eyJhbG...y5w")
```

#### Supported claims

- Issuer (`iss`) Claim
- Expiration Time (`exp`) Claim

## License

JWT is licensed under the BSD license. See [LICENSE](LICENSE) for more info.

