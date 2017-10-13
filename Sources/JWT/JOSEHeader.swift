//
//  JOSEHeader.swift
//  JWT
//
//  Created by Kyle Fuller on 02/12/2016.
//  Copyright © 2016 Cocode. All rights reserved.
//

import Foundation


struct JOSEHeader: Codable {
  /// The "alg" (algorithm) identifies the cryptographic algorithm used to secure the JWS
  var algorithm: String?

  /// jwu
  // TODO

  /// jwk
  // TODO

  /// The "kid" (key ID) is a hint indicating which key was used to secure the JWS
  var keyID: String?

  /// x5u
  // TODO

  /// x5c
  // TODO

  /// x5t
  // TODO

  /// x5t#S256
  // TODO

  /// The "typ" (type) is used by JWS applications to declare the media type [IANA.MediaTypes] of this complete JWS
  var type: String?

  /// The "cty" (content type) is used by JWS application to declare the media type [IANA.MediaTypes] of the secured content (the payload).
  var contentType: String?

  /// The "crit" (critical) indicates that extensions to JWS, JWE and/or [JWA] are being used that MUST be understood and processed
  // TODO

  init(from decoder: Decoder) throws {
    let container = try decoder.container(keyedBy: CodingKeys.self)
    algorithm = try container.decodeIfPresent(String.self, forKey: .algorithm)
    keyID = try container.decodeIfPresent(String.self, forKey: .keyID)
    type = try container.decodeIfPresent(String.self, forKey: .type)
    contentType = try container.decodeIfPresent(String.self, forKey: .contentType)
  }

  func encode(to encoder: Encoder) throws {
    var container = encoder.container(keyedBy: CodingKeys.self)
    try container.encodeIfPresent(algorithm, forKey: .algorithm)
    try container.encodeIfPresent(keyID, forKey: .keyID)
    try container.encodeIfPresent(type, forKey: .type)
    try container.encodeIfPresent(contentType, forKey: .contentType)
  }

  enum CodingKeys: String, CodingKey {
    case algorithm = "alg"
    case keyID = "kid"
    case type = "typ"
    case contentType = "cty"
  }
}
