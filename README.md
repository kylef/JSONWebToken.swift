# JSON Web Token

Fork of https://github.com/kylef/JSONWebToken.swift that resolves the issue "Get raw claim set data" ((https://github.com/kylef/JSONWebToken.swift/issues/69)

## Installation

=======
Swift Pacakage Manager is the recommended installation method for JSONWebToken, [CocoaPods](http://cocoapods.org/) is also supported.

```ruby
pod 'JSONWebToken'
```

**NOTE:** *Carthage may be supported, however support will not be provided for this installation method, use at your own risk if you know how it works.*

## Usage

```swift
import JWT
```

### Encoding a claim

```swift
JWT.encode(claims: ["my": "payload"], algorithm: .hs256("secret".data(using: .utf8)!))
```

#### Encoding a claim set

```swift
var claims = ClaimSet()
claims.issuer = "fuller.li"
claims.issuedAt = Date()
claims["custom"] = "Hi"

JWT.encode(claims: claims, algorithm: .hs256("secret".data(using: .utf8)!))
```

#### Building a JWT with the builder pattern

```swift
JWT.encode(.hs256("secret".data(using: .utf8))) { builder in
  builder.issuer = "fuller.li"
  builder.issuedAt = Date()
  builder["custom"] = "Hi"
}
```

### Decoding a JWT

When decoding a JWT, you must supply one or more algorithms and keys.

```swift
do {
  let claims: ClaimSet = try JWT.decode("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.2_8pWJfyPup0YwOXK7g9Dn0cF1E3pdn299t4hSeJy5w", algorithm: .hs256("secret".data(using: .utf8)!))
  print(claims)
} catch {
  print("Failed to decode JWT: \(error)")
}
```

When the JWT may be signed with one out of many algorithms or keys:

```swift
try JWT.decode("eyJh...5w", algorithms: [
  .hs256("secret".data(using: .utf8)!),
  .hs256("secret2".data(using: .utf8)!),
  .hs512("secure".data(using: .utf8)!)
])
```

You might also want to give your iat, exp and nbf checks some kind of leeway to account for skewed clocks. You can do this by passing a `leeway` parameter like this:

```swift
try JWT.decode("eyJh...5w", algorithm: .hs256("secret".data(using: .utf8)!), leeway: 10)
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

- `none` - Unsecured JWTs
- `hs256` - HMAC using SHA-256 hash algorithm (default)
- `hs384` - HMAC using SHA-384 hash algorithm
- `hs512` - HMAC using SHA-512 hash algorithm
        
## License

JSONWebToken is licensed under the BSD license. See [LICENSE](LICENSE) for more info.
