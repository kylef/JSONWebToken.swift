//
//  JOSEHeader.swift
//  JWT
//
//  Created by Kyle Fuller on 02/12/2016.
//  Copyright © 2016 Cocode. All rights reserved.
//

import Foundation


struct JOSEHeader: Codable {
  var type: String?
  var algorithm: String?

  init(from decoder: Decoder) throws {
    let container = try decoder.container(keyedBy: CodingKeys.self)
    type = try container.decodeIfPresent(String.self, forKey: .type)
    algorithm = try container.decodeIfPresent(String.self, forKey: .algorithm)
  }

  func encode(to encoder: Encoder) throws {
    var container = encoder.container(keyedBy: CodingKeys.self)
    try container.encodeIfPresent(type, forKey: .type)
    try container.encodeIfPresent(algorithm, forKey: .algorithm)
  }

  enum CodingKeys: String, CodingKey {
    case type = "typ"
    case algorithm = "alg"
  }
}
