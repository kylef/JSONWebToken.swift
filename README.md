# JSON Web Token

[![Build Status](http://img.shields.io/travis/kylef/JWT.swift/master.svg?style=flat)](https://travis-ci.org/kylef/JWT.swift)

Swift implementation of [JSON Web Token](https://tools.ietf.org/html/draft-ietf-oauth-json-web-token-32).

## Installation

[CocoaPods](http://cocoapods.org/) is the recommended installation method.

```ruby
pod 'JWT'
```

## Usage

```swift
import JWT
```

### Encoding a claim

```swift
JWT.encode(["my": "payload"], .HS256("secret"))
```

### Decoding a JWT

```swift
JWT.decode("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.2_8pWJfyPup0YwOXK7g9Dn0cF1E3pdn299t4hSeJy5w")
```

#### Supported claims

The library supports validating the following claims:

- Issuer (`iss`) Claim
- Expiration Time (`exp`) Claim
- Not Before (`nbf`) Claim
- Issued At (`iat`) Claim
- Audience (`aud`) Claim

### Algorithms

This library supports the following algorithms:

- None - Unsecured JWTs
- HS256 - HMAC using SHA-256 hash algorithm (default)

## License

JWT is licensed under the BSD license. See [LICENSE](LICENSE) for more info.

