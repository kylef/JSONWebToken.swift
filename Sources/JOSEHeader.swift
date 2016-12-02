//
//  JOSEHeader.swift
//  JWT
//
//  Created by Kyle Fuller on 02/12/2016.
//  Copyright © 2016 Cocode. All rights reserved.
//

import Foundation


struct JOSEHeader {
  var parameters: [String: Any]

  init(parameters: [String: Any]) {
    self.parameters = parameters
  }

  var algorithm: String? {
    get {
      return parameters["alg"] as? String
    }

    set {
      parameters["alg"] = newValue
    }
  }
}
