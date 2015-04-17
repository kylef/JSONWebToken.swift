# JSON Web Token

[![Build Status](http://img.shields.io/travis/kylef/JSONWebToken.swift/master.svg?style=flat)](https://travis-ci.org/kylef/JSONWebToken.swift)

Swift implementation of [JSON Web Token](https://tools.ietf.org/html/draft-ietf-oauth-json-web-token-32).

## Installation

[CocoaPods](http://cocoapods.org/) is the recommended installation method.

```ruby
pod 'JSONWebToken'
```

## Usage

```swift
import JWT
```

### Encoding a claim

```swift
JWT.encode(["my": "payload"], .HS256("secret"))
```

#### Building a JWT with the builder pattern

```swift
JWT.encode(.HS256("secret")) { builder in
  builder.issuer = "fuller.li"
  builder.issuedAt = NSDate()
  builder["custom"] = "Hi"
}
```

### Decoding a JWT

When decoding a JWT, you must supply one or more algorithms and keys.

```swift
JWT.decode("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.2_8pWJfyPup0YwOXK7g9Dn0cF1E3pdn299t4hSeJy5w", .HS256("secret"))
```

When the JWT may be signed with one out of many algorithms or keys:

```swift
JWT.decode("eyJh...5w", [.HS256("secret"), .HS256("secret2"), .HS512("secure")])
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
- HS384 - HMAC using SHA-384 hash algorithm
- HS512 - HMAC using SHA-384 hash algorithm

## License

JSONWebToken is licensed under the BSD license. See [LICENSE](LICENSE) for more info.

