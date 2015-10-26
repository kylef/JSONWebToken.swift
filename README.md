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
JWT.encode(["my": "payload"], algorithm: .HS256("secret"))
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

When decoding a JWT, you must supply only one algorithm as a temporary fix (until JWT spec is modified to
verify signature with Key ID) for critical vulnerability as identified by Tim McClean in this [article](https://auth0.com/blog/2015/03/31/critical-vulnerabilities-in-json-web-token-libraries/)

```swift
do {
  let payload = try JWT.decode("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.2_8pWJfyPup0YwOXK7g9Dn0cF1E3pdn299t4hSeJy5w", algorithm: .HS256("secret"))
  print(payload)
} catch {
  print("Failed to decode JWT: \(error)")
}
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
- HS512 - HMAC using SHA-512 hash algorithm

## License

JSONWebToken is licensed under the BSD license. See [LICENSE](LICENSE) for more info.

