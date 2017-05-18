import Foundation

open class SwKeyStore {

	public enum SecError: OSStatus, Error {
		case unimplemented = -4
		case param = -50
		case allocate = -108
		case notAvailable = -25291
		case authFailed = -25293
		case duplicateItem = -25299
		case itemNotFound = -25300
		case interactionNotAllowed = -25308
		case decode = -26275
		case missingEntitlement = -34018

		public static var debugLevel = 1

		init(_ status: OSStatus, function: String = #function, file: String = #file, line: Int = #line) {
			self = SecError(rawValue: status)!
			if SecError.debugLevel > 0 {
				print("\(file):\(line): [\(function)] \(self._domain): \(self) (\(self.rawValue))")
			}
		}
		init(_ type: SecError, function: String = #function, file: String = #file, line: Int = #line) {
			self = type
			if SecError.debugLevel > 0 {
				print("\(file):\(line): [\(function)] \(self._domain): \(self) (\(self.rawValue))")
			}
		}
	}

	open static func upsertKey(_ pemKey: String, keyTag: String,
	                             options: [NSString : AnyObject] = [:]) throws {
		let pemKeyAsData = pemKey.data(using: String.Encoding.utf8)!

		var parameters: [NSString : AnyObject] = [
			kSecClass: kSecClassKey,
			kSecAttrKeyType: kSecAttrKeyTypeRSA,
			kSecAttrIsPermanent: true as AnyObject,
			kSecAttrApplicationTag: keyTag as AnyObject,
			kSecValueData: pemKeyAsData as AnyObject
		]
		options.forEach { k, v in
			parameters[k] = v
		}

		var status = SecItemAdd(parameters as CFDictionary, nil)
		if status == errSecDuplicateItem {
			try delKey(keyTag)
			status = SecItemAdd(parameters as CFDictionary, nil)
		}
		guard status == errSecSuccess else { throw SecError(status) }
	}

	open static func getKey(_ keyTag: String) throws -> String {
		let parameters: [NSString : AnyObject] = [
			kSecClass : kSecClassKey,
			kSecAttrKeyType : kSecAttrKeyTypeRSA,
			kSecAttrApplicationTag : keyTag as AnyObject,
			kSecReturnData : true as AnyObject
		]
		var data: AnyObject?
		let status = SecItemCopyMatching(parameters as CFDictionary, &data)
		guard status == errSecSuccess else { throw SecError(status) }

		guard let pemKeyAsData = data as? Data else {
			throw SecError(.decode)
		}
		guard let result = String(data: pemKeyAsData, encoding: String.Encoding.utf8) else {
			throw SecError(.decode)
		}
		return result
	}

	open static func delKey(_ keyTag: String) throws {
		let parameters: [NSString : AnyObject] = [
			kSecClass : kSecClassKey,
			kSecAttrApplicationTag: keyTag as AnyObject
		]
		let status = SecItemDelete(parameters as CFDictionary)
		guard status == errSecSuccess else { throw SecError(status) }
	}
}

open class SwKeyConvert {

	public enum SwError: Error {
		case invalidKey
		case badPassphrase
		case keyNotEncrypted

		public static var debugLevel = 1

		init(_ type: SwError, function: String = #function, file: String = #file, line: Int = #line) {
			self = type
			if SwError.debugLevel > 0 {
				print("\(file):\(line): [\(function)] \(self._domain): \(self)")
			}
		}
	}

	open class PrivateKey {

		open static func pemToPKCS1DER(_ pemKey: String) throws -> Data {
			guard let derKey = try? PEM.PrivateKey.toDER(pemKey) else {
				throw SwError(.invalidKey)
			}
			guard let pkcs1DERKey = PKCS8.PrivateKey.stripHeaderIfAny(derKey) else {
				throw SwError(.invalidKey)
			}
			return pkcs1DERKey
		}

		open static func derToPKCS1PEM(_ derKey: Data) -> String {
			return PEM.PrivateKey.toPEM(derKey)
		}

		public typealias EncMode = PEM.EncryptedPrivateKey.EncMode

		open static func encryptPEM(_ pemKey: String, passphrase: String,
		                              mode: EncMode) throws -> String {
			do {
				let derKey = try PEM.PrivateKey.toDER(pemKey)
				return PEM.EncryptedPrivateKey.toPEM(derKey, passphrase: passphrase, mode: mode)
			} catch {
				throw SwError(.invalidKey)
			}
		}

		open static func decryptPEM(_ pemKey: String, passphrase: String) throws -> String {
			do {
				let derKey = try PEM.EncryptedPrivateKey.toDER(pemKey, passphrase: passphrase)
				return PEM.PrivateKey.toPEM(derKey)
			} catch PEM.SwError.badPassphrase {
				throw SwError(.badPassphrase)
			} catch PEM.SwError.keyNotEncrypted {
				throw SwError(.keyNotEncrypted)
			} catch {
				throw SwError(.invalidKey)
			}
		}
	}

	open class PublicKey {

		open static func pemToPKCS1DER(_ pemKey: String) throws -> Data {
			guard let derKey = try? PEM.PublicKey.toDER(pemKey) else {
				throw SwError(.invalidKey)
			}
			guard let pkcs1DERKey = PKCS8.PublicKey.stripHeaderIfAny(derKey) else {
				throw SwError(.invalidKey)
			}
			return pkcs1DERKey
		}

		open static func derToPKCS1PEM(_ derKey: Data) -> String {
			return PEM.PublicKey.toPEM(derKey)
		}

		open static func derToPKCS8PEM(_ derKey: Data) -> String {
			let pkcs8Key = PKCS8.PublicKey.addHeader(derKey)
			return PEM.PublicKey.toPEM(pkcs8Key)
		}

	}

}

open class PKCS8 {

	open class PrivateKey {

		//https://lapo.it/asn1js/
		open static func getPKCS1DEROffset(_ derKey: Data) -> Int? {
			let bytes = derKey.bytesView

			var offset = 0
			guard bytes.length > offset else { return nil }
			guard bytes[offset] == 0x30 else { return nil }

			offset += 1

			guard bytes.length > offset else { return nil }
			if bytes[offset] > 0x80 {
				offset += Int(bytes[offset]) - 0x80
			}
			offset += 1

			guard bytes.length > offset else { return nil }
			guard bytes[offset] == 0x02 else { return nil }

			offset += 3

			//without PKCS8 header
			guard bytes.length > offset else { return nil }
			if bytes[offset] == 0x02 {
				return 0
			}

			let OID: [UInt8] = [0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86,
			                    0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00]

			guard bytes.length > offset + OID.count else { return nil }
			let slice = derKey.bytesViewRange(NSRange(location: offset, length: OID.count))

			guard OID.elementsEqual(slice) else { return nil }

			offset += OID.count

			guard bytes.length > offset else { return nil }
			guard bytes[offset] == 0x04 else { return nil }

			offset += 1

			guard bytes.length > offset else { return nil }
			if bytes[offset] > 0x80 {
				offset += Int(bytes[offset]) - 0x80
			}
			offset += 1

			guard bytes.length > offset else { return nil }
			guard bytes[offset] == 0x30 else { return nil }

			return offset
		}

		open static func stripHeaderIfAny(_ derKey: Data) -> Data? {
			guard let offset = getPKCS1DEROffset(derKey) else {
				return nil
			}
			return derKey.subdata(in: offset..<derKey.count)
		}

		open static func hasCorrectHeader(_ derKey: Data) -> Bool {
			return getPKCS1DEROffset(derKey) != nil
		}

	}

	open class PublicKey {

		open static func addHeader(_ derKey: Data) -> Data {
			var result = Data()

			let encodingLength: Int = encodedOctets(derKey.count + 1).count
			let OID: [UInt8] = [0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86,
			                    0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00]

			var builder: [UInt8] = []

			// ASN.1 SEQUENCE
			builder.append(0x30)

			// Overall size, made of OID + bitstring encoding + actual key
			let size = OID.count + 2 + encodingLength + derKey.count
			let encodedSize = encodedOctets(size)
			builder.append(contentsOf: encodedSize)
			result.append(builder, count: builder.count)
			result.append(OID, count: OID.count)
			builder.removeAll(keepingCapacity: false)

			builder.append(0x03)
			builder.append(contentsOf: encodedOctets(derKey.count + 1))
			builder.append(0x00)
			result.append(builder, count: builder.count)

			// Actual key bytes
			result.append(derKey)

			return result
		}

		//https://lapo.it/asn1js/
		open static func getPKCS1DEROffset(_ derKey: Data) -> Int? {
			let bytes = derKey.bytesView

			var offset = 0
			guard bytes.length > offset else { return nil }
			guard bytes[offset] == 0x30 else { return nil }

			offset += 1

			guard bytes.length > offset else { return nil }
			if bytes[offset] > 0x80 {
				offset += Int(bytes[offset]) - 0x80
			}
			offset += 1

			//without PKCS8 header
			guard bytes.length > offset else { return nil }
			if bytes[offset] == 0x02 {
				return 0
			}

			let OID: [UInt8] = [0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86,
			                    0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00]

			guard bytes.length > offset + OID.count else { return nil }
			let slice = derKey.bytesViewRange(NSRange(location: offset, length: OID.count))

			guard OID.elementsEqual(slice) else { return nil }
			offset += OID.count

			// Type
			guard bytes.length > offset else { return nil }
			guard bytes[offset] == 0x03 else { return nil }

			offset += 1

			guard bytes.length > offset else { return nil }
			if bytes[offset] > 0x80 {
				offset += Int(bytes[offset]) - 0x80
			}
			offset += 1

			// Contents should be separated by a null from the header
			guard bytes.length > offset else { return nil }
			guard bytes[offset] == 0x00 else { return nil }

			offset += 1
			guard bytes.length > offset else { return nil }

			return offset
		}

		open static func stripHeaderIfAny(_ derKey: Data) -> Data? {
			guard let offset = getPKCS1DEROffset(derKey) else {
				return nil
			}
			return derKey.subdata(in: offset..<derKey.count)
		}

		open static func hasCorrectHeader(_ derKey: Data) -> Bool {
			return getPKCS1DEROffset(derKey) != nil
		}

		fileprivate static func encodedOctets(_ int: Int) -> [UInt8] {
			// Short form
			if int < 128 {
				return [UInt8(int)]
			}

			// Long form
			let i = (int / 256) + 1
			var len = int
			var result: [UInt8] = [UInt8(i + 0x80)]

			for _ in 0..<i {
				result.insert(UInt8(len & 0xFF), at: 1)
				len = len >> 8
			}

			return result
		}
	}
}

open class PEM {

	public enum SwError: Error {
		case parse(String)
		case badPassphrase
		case keyNotEncrypted

		public static var debugLevel = 1

		init(_ type: SwError, function: String = #function, file: String = #file, line: Int = #line) {
			self = type
			if SwError.debugLevel > 0 {
				print("\(file):\(line): [\(function)] \(self._domain): \(self)")
			}
		}
	}

	open class PrivateKey {

		open static func toDER(_ pemKey: String) throws -> Data {
			guard let strippedKey = stripHeader(pemKey) else {
				throw SwError(.parse("header"))
			}
			guard let data = PEM.base64Decode(strippedKey) else {
				throw SwError(.parse("base64decode"))
			}
			return data
		}

		open static func toPEM(_ derKey: Data) -> String {
			let base64 = PEM.base64Encode(derKey)
			return addRSAHeader(base64)
		}

		fileprivate static let prefix = "-----BEGIN PRIVATE KEY-----\n"
		fileprivate static let suffix = "\n-----END PRIVATE KEY-----"
		fileprivate static let rsaPrefix = "-----BEGIN RSA PRIVATE KEY-----\n"
		fileprivate static let rsaSuffix = "\n-----END RSA PRIVATE KEY-----"

		fileprivate static func addHeader(_ base64: String) -> String {
			return prefix + base64 + suffix
		}

		fileprivate static func addRSAHeader(_ base64: String) -> String {
			return rsaPrefix + base64 + rsaSuffix
		}

		fileprivate static func stripHeader(_ pemKey: String) -> String? {
			return PEM.stripHeaderFooter(pemKey, header: prefix, footer: suffix) ??
				PEM.stripHeaderFooter(pemKey, header: rsaPrefix, footer: rsaSuffix)
		}
	}

	open class PublicKey {

		open static func toDER(_ pemKey: String) throws -> Data {
			guard let strippedKey = stripHeader(pemKey) else {
				throw SwError(.parse("header"))
			}
			guard let data = PEM.base64Decode(strippedKey) else {
				throw SwError(.parse("base64decode"))
			}
			return data
		}

		open static func toPEM(_ derKey: Data) -> String {
			let base64 = PEM.base64Encode(derKey)
			return addHeader(base64)
		}

		fileprivate static let pemPrefix = "-----BEGIN PUBLIC KEY-----\n"
		fileprivate static let pemSuffix = "\n-----END PUBLIC KEY-----"

		fileprivate static func addHeader(_ base64: String) -> String {
			return pemPrefix + base64 + pemSuffix
		}

		fileprivate static func stripHeader(_ pemKey: String) -> String? {
			return PEM.stripHeaderFooter(pemKey, header: pemPrefix, footer: pemSuffix)
		}
	}

	open class EncryptedPrivateKey {

		public enum EncMode {
			case aes128CBC, aes256CBC
		}

		open static func toDER(_ pemKey: String, passphrase: String) throws -> Data {
			guard let strippedKey = PrivateKey.stripHeader(pemKey) else {
				throw SwError(.parse("header"))
			}
			guard let mode = getEncMode(strippedKey) else {
				throw SwError(.keyNotEncrypted)
			}
			guard let iv = getIV(strippedKey) else {
				throw SwError(.parse("iv"))
			}
			let aesKey = getAESKey(mode, passphrase: passphrase, iv: iv)
            let base64Data = strippedKey.substring(
                from: strippedKey.index(strippedKey.startIndex, offsetBy:aesHeaderLength))
			guard let data = PEM.base64Decode(base64Data) else {
				throw SwError(.parse("base64decode"))
			}
			guard let decrypted = try? decryptKey(data, key: aesKey, iv: iv) else {
				throw SwError(.badPassphrase)
			}
			guard PKCS8.PrivateKey.hasCorrectHeader(decrypted) else {
				throw SwError(.badPassphrase)
			}
			return decrypted
		}

		open static func toPEM(_ derKey: Data, passphrase: String, mode: EncMode) -> String {
			let iv = CC.generateRandom(16)
			let aesKey = getAESKey(mode, passphrase: passphrase, iv: iv)
			let encrypted = encryptKey(derKey, key: aesKey, iv: iv)
			let encryptedDERKey = addEncryptHeader(encrypted, iv: iv, mode: mode)
			return PrivateKey.addRSAHeader(encryptedDERKey)
		}

		fileprivate static let aes128CBCInfo = "Proc-Type: 4,ENCRYPTED\nDEK-Info: AES-128-CBC,"
		fileprivate static let aes256CBCInfo = "Proc-Type: 4,ENCRYPTED\nDEK-Info: AES-256-CBC,"
		fileprivate static let aesInfoLength = aes128CBCInfo.characters.count
		fileprivate static let aesIVInHexLength = 32
		fileprivate static let aesHeaderLength = aesInfoLength + aesIVInHexLength

		fileprivate static func addEncryptHeader(_ key: Data, iv: Data, mode: EncMode) -> String {
			return getHeader(mode) + iv.hexadecimalString() + "\n\n" + PEM.base64Encode(key)
		}

		fileprivate static func getHeader(_ mode: EncMode) -> String {
			switch mode {
			case .aes128CBC: return aes128CBCInfo
			case .aes256CBC: return aes256CBCInfo
			}
		}

		fileprivate static func getEncMode(_ strippedKey: String) -> EncMode? {
			if strippedKey.hasPrefix(aes128CBCInfo) {
				return .aes128CBC
			}
			if strippedKey.hasPrefix(aes256CBCInfo) {
				return .aes256CBC
			}
			return nil
		}

		fileprivate static func getIV(_ strippedKey: String) -> Data? {
			let ivInHex = strippedKey.substring(
				with: strippedKey.index(strippedKey.startIndex,
				                        offsetBy:aesInfoLength) ..< strippedKey.index(strippedKey.startIndex,
				                                                                      offsetBy:aesHeaderLength))
			return ivInHex.dataFromHexadecimalString()
		}

		fileprivate static func getAESKey(_ mode: EncMode, passphrase: String, iv: Data) -> Data {
			switch mode {
			case .aes128CBC: return getAES128Key(passphrase, iv: iv)
			case .aes256CBC: return getAES256Key(passphrase, iv: iv)
			}
		}

		fileprivate static func getAES128Key(_ passphrase: String, iv: Data) -> Data {
			//128bit_Key = MD5(Passphrase + Salt)
			let pass = passphrase.data(using: String.Encoding.utf8)!
			let salt = iv.subdata(in: 0..<8)

			var key = pass
			key.append(salt)
			return CC.digest(key, alg: .md5)
		}

		fileprivate static func getAES256Key(_ passphrase: String, iv: Data) -> Data {
			//128bit_Key = MD5(Passphrase + Salt)
			//256bit_Key = 128bit_Key + MD5(128bit_Key + Passphrase + Salt)
			let pass = passphrase.data(using: String.Encoding.utf8)!
			let salt = iv.subdata(in: 0 ..< 8)

			var first = pass
			first.append(salt)
			let aes128Key = CC.digest(first, alg: .md5)

			var sec = aes128Key
			sec.append(pass)
			sec.append(salt)

			var aes256Key = aes128Key
			aes256Key.append(CC.digest(sec, alg: .md5))
			return aes256Key
		}

		fileprivate static func encryptKey(_ data: Data, key: Data, iv: Data) -> Data {
			return try! CC.crypt(
				.encrypt, blockMode: .cbc, algorithm: .aes, padding: .pkcs7Padding,
				data: data, key: key, iv: iv)
		}

		fileprivate static func decryptKey(_ data: Data, key: Data, iv: Data) throws -> Data {
			return try CC.crypt(
				.decrypt, blockMode: .cbc, algorithm: .aes, padding: .pkcs7Padding,
				data: data, key: key, iv: iv)
		}

	}

	fileprivate static func stripHeaderFooter(_ data: String, header: String, footer: String) -> String? {
		guard data.hasPrefix(header) else {
			return nil
		}
		guard let r = data.range(of: footer) else {
			return nil
		}
		return data.substring(with: header.endIndex..<r.lowerBound)
	}

	fileprivate static func base64Decode(_ base64Data: String) -> Data? {
		return Data(base64Encoded: base64Data, options: [.ignoreUnknownCharacters])
	}

	fileprivate static func base64Encode(_ key: Data) -> String {
		return key.base64EncodedString(
			options: [.lineLength64Characters, .endLineWithLineFeed])
	}

}

open class CC {

	public typealias CCCryptorStatus = Int32
	public enum CCError: CCCryptorStatus, Error {
		case paramError = -4300
		case bufferTooSmall = -4301
		case memoryFailure = -4302
		case alignmentError = -4303
		case decodeError = -4304
		case unimplemented = -4305
		case overflow = -4306
		case rngFailure = -4307

		public static var debugLevel = 1

		init(_ status: CCCryptorStatus, function: String = #function,
		       file: String = #file, line: Int = #line) {
			self = CCError(rawValue: status)!
			if CCError.debugLevel > 0 {
				print("\(file):\(line): [\(function)] \(self._domain): \(self) (\(self.rawValue))")
			}
		}
		init(_ type: CCError, function: String = #function, file: String = #file, line: Int = #line) {
			self = type
			if CCError.debugLevel > 0 {
				print("\(file):\(line): [\(function)] \(self._domain): \(self) (\(self.rawValue))")
			}
		}
	}

	open static func generateRandom(_ size: Int) -> Data {
		var data = Data(count: size)
        data.withUnsafeMutableBytes { (dataBytes: UnsafeMutablePointer<UInt8>) -> Void in
            _ = CCRandomGenerateBytes!(dataBytes, size)
        }
		return data
	}

	public typealias CCDigestAlgorithm = UInt32
	public enum DigestAlgorithm: CCDigestAlgorithm {
		case none = 0
		case md5 = 3
		case rmd128 = 4, rmd160 = 5, rmd256 = 6, rmd320 = 7
		case sha1 = 8
		case sha224 = 9, sha256 = 10, sha384 = 11, sha512 = 12

		var length: Int {
			return CCDigestGetOutputSize!(self.rawValue)
		}
	}

	open static func digest(_ data: Data, alg: DigestAlgorithm) -> Data {
		var output = Data(count: alg.length)
        output.withUnsafeMutableBytes { (outputBytes: UnsafeMutablePointer<UInt8>) -> Void in
            _ = CCDigest!(alg.rawValue,
                          (data as NSData).bytes,
                          data.count,
                          outputBytes)
        }
		return output
	}

	public typealias CCHmacAlgorithm = UInt32
	public enum HMACAlg: CCHmacAlgorithm {
		case sha1, md5, sha256, sha384, sha512, sha224

		var digestLength: Int {
			switch self {
			case .sha1: return 20
			case .md5: return 16
			case .sha256: return 32
			case .sha384: return 48
			case .sha512: return 64
			case .sha224: return 28
			}
		}
	}

	open static func HMAC(_ data: Data, alg: HMACAlg, key: Data) -> Data {
		var buffer = Data(count: alg.digestLength)
        buffer.withUnsafeMutableBytes { (bufferBytes: UnsafeMutablePointer<UInt8>) -> Void in
            CCHmac!(alg.rawValue,
                    (key as NSData).bytes, key.count,
                    (data as NSData).bytes, data.count,
                    bufferBytes)
        }
		return buffer
	}

	public typealias CCOperation = UInt32
	public enum OpMode: CCOperation {
		case encrypt = 0, decrypt
	}

	public typealias CCMode = UInt32
	public enum BlockMode: CCMode {
		case ecb = 1, cbc, cfb, ctr, f8, lrw, ofb, xts, rc4, cfb8
		var needIV: Bool {
			switch self {
			case .cbc, .cfb, .ctr, .ofb, .cfb8: return true
			default: return false
			}
		}
	}

	public enum AuthBlockMode: CCMode {
		case gcm = 11, ccm
	}

	public typealias CCAlgorithm = UInt32
	public enum Algorithm: CCAlgorithm {
		case aes = 0, des, threeDES, cast, rc4, rc2, blowfish

		var blockSize: Int? {
			switch self {
			case .aes: return 16
			case .des: return 8
			case .threeDES: return 8
			case .cast: return 8
			case .rc2: return 8
			case .blowfish: return 8
			default: return nil
			}
		}
	}

	public typealias CCPadding = UInt32
	public enum Padding: CCPadding {
		case noPadding = 0, pkcs7Padding
	}

	open static func crypt(_ opMode: OpMode, blockMode: BlockMode,
	                         algorithm: Algorithm, padding: Padding,
	                         data: Data, key: Data, iv: Data) throws -> Data {
		if blockMode.needIV {
			guard iv.count == algorithm.blockSize else { throw CCError(.paramError) }
		}

		var cryptor: CCCryptorRef? = nil
		var status = CCCryptorCreateWithMode!(
			opMode.rawValue, blockMode.rawValue,
			algorithm.rawValue, padding.rawValue,
			(iv as NSData).bytes, (key as NSData).bytes, key.count,
			nil, 0, 0,
			CCModeOptions(), &cryptor)
		guard status == noErr else { throw CCError(status) }

		defer { _ = CCCryptorRelease!(cryptor!) }

		let needed = CCCryptorGetOutputLength!(cryptor!, data.count, true)
		var result = Data(count: needed)
		var updateLen: size_t = 0
        status = result.withUnsafeMutableBytes({ (resultBytes: UnsafeMutablePointer<UInt8>) -> CCCryptorStatus in
            return CCCryptorUpdate!(
                cryptor!,
                (data as NSData).bytes, data.count,
                resultBytes, result.count,
                &updateLen)
        })
		guard status == noErr else { throw CCError(status) }


		var finalLen: size_t = 0
        status = result.withUnsafeMutableBytes({ (resultBytes: UnsafeMutablePointer<UInt8>) -> CCCryptorStatus in
            return CCCryptorFinal!(
                cryptor!,
                resultBytes + updateLen,
                result.count - updateLen,
                &finalLen)
        })
		guard status == noErr else { throw CCError(status) }


		result.count = updateLen + finalLen
		return result
	}

	//The same behaviour as in the CCM pdf
	//http://csrc.nist.gov/publications/nistpubs/800-38C/SP800-38C_updated-July20_2007.pdf
	open static func cryptAuth(_ opMode: OpMode, blockMode: AuthBlockMode, algorithm: Algorithm,
	                             data: Data, aData: Data,
	                             key: Data, iv: Data, tagLength: Int) throws -> Data {
		let cryptFun = blockMode == .gcm ? GCM.crypt : CCM.crypt
		if opMode == .encrypt {
			let (cipher, tag) = try cryptFun(opMode, algorithm, data,
			                                 key, iv, aData, tagLength)
			var result = cipher
			result.append(tag)
			return result
		} else {
			let cipher = data.subdata(in: 0..<(data.count - tagLength))
			let tag = data.subdata(
				in: (data.count - tagLength)..<data.count)
			let (plain, vTag) = try cryptFun(opMode, algorithm, cipher,
			                                 key, iv, aData, tagLength)
			guard tag == vTag else {
				throw CCError(.decodeError)
			}
			return plain
		}
	}

	open static func digestAvailable() -> Bool {
		return CCDigest != nil &&
			CCDigestGetOutputSize != nil
	}

	open static func randomAvailable() -> Bool {
		return CCRandomGenerateBytes != nil
	}

	open static func hmacAvailable() -> Bool {
		return CCHmac != nil
	}

	open static func cryptorAvailable() -> Bool {
		return CCCryptorCreateWithMode != nil &&
			CCCryptorGetOutputLength != nil &&
			CCCryptorUpdate != nil &&
			CCCryptorFinal != nil &&
			CCCryptorRelease != nil
	}

	open static func available() -> Bool {
		return digestAvailable() &&
			randomAvailable() &&
			hmacAvailable() &&
			cryptorAvailable() &&
			KeyDerivation.available() &&
			KeyWrap.available() &&
			RSA.available() &&
			DH.available() &&
			EC.available() &&
			CRC.available() &&
			CMAC.available() &&
			GCM.available() &&
			CCM.available()
	}

	fileprivate typealias CCCryptorRef = UnsafeRawPointer
	fileprivate typealias CCRNGStatus = CCCryptorStatus
	fileprivate typealias CC_LONG = UInt32
	fileprivate typealias CCModeOptions = UInt32

	fileprivate typealias CCRandomGenerateBytesT = @convention(c) (
		_ bytes: UnsafeMutableRawPointer,
		_ count: size_t) -> CCRNGStatus
	fileprivate typealias CCDigestGetOutputSizeT = @convention(c) (
		_ algorithm: CCDigestAlgorithm) -> size_t
	fileprivate typealias CCDigestT = @convention(c) (
		_ algorithm: CCDigestAlgorithm,
		_ data: UnsafeRawPointer,
		_ dataLen: size_t,
		_ output: UnsafeMutableRawPointer) -> CInt

	fileprivate typealias CCHmacT = @convention(c) (
		_ algorithm: CCHmacAlgorithm,
		_ key: UnsafeRawPointer,
		_ keyLength: Int,
		_ data: UnsafeRawPointer,
		_ dataLength: Int,
		_ macOut: UnsafeMutableRawPointer) -> Void
	fileprivate typealias CCCryptorCreateWithModeT = @convention(c)(
		_ op: CCOperation,
		_ mode: CCMode,
		_ alg: CCAlgorithm,
		_ padding: CCPadding,
		_ iv: UnsafeRawPointer?,
		_ key: UnsafeRawPointer, _ keyLength: Int,
		_ tweak: UnsafeRawPointer?, _ tweakLength: Int,
		_ numRounds: Int32, _ options: CCModeOptions,
		_ cryptorRef: UnsafeMutablePointer<CCCryptorRef?>) -> CCCryptorStatus
	fileprivate typealias CCCryptorGetOutputLengthT = @convention(c)(
		_ cryptorRef: CCCryptorRef,
		_ inputLength: size_t,
		_ final: Bool) -> size_t
	fileprivate typealias CCCryptorUpdateT = @convention(c)(
		_ cryptorRef: CCCryptorRef,
		_ dataIn: UnsafeRawPointer,
		_ dataInLength: Int,
		_ dataOut: UnsafeMutableRawPointer,
		_ dataOutAvailable: Int,
		_ dataOutMoved: UnsafeMutablePointer<Int>) -> CCCryptorStatus
	fileprivate typealias CCCryptorFinalT = @convention(c)(
		_ cryptorRef: CCCryptorRef,
		_ dataOut: UnsafeMutableRawPointer,
		_ dataOutAvailable: Int,
		_ dataOutMoved: UnsafeMutablePointer<Int>) -> CCCryptorStatus
	fileprivate typealias CCCryptorReleaseT = @convention(c)
		(_ cryptorRef: CCCryptorRef) -> CCCryptorStatus


	fileprivate static let dl = dlopen("/usr/lib/system/libcommonCrypto.dylib", RTLD_NOW)
	fileprivate static let CCRandomGenerateBytes: CCRandomGenerateBytesT? =
		getFunc(dl!, f: "CCRandomGenerateBytes")
	fileprivate static let CCDigestGetOutputSize: CCDigestGetOutputSizeT? =
		getFunc(dl!, f: "CCDigestGetOutputSize")
	fileprivate static let CCDigest: CCDigestT? = getFunc(dl!, f: "CCDigest")
	fileprivate static let CCHmac: CCHmacT? = getFunc(dl!, f: "CCHmac")
	fileprivate static let CCCryptorCreateWithMode: CCCryptorCreateWithModeT? =
		getFunc(dl!, f: "CCCryptorCreateWithMode")
	fileprivate static let CCCryptorGetOutputLength: CCCryptorGetOutputLengthT? =
		getFunc(dl!, f: "CCCryptorGetOutputLength")
	fileprivate static let CCCryptorUpdate: CCCryptorUpdateT? =
		getFunc(dl!, f: "CCCryptorUpdate")
	fileprivate static let CCCryptorFinal: CCCryptorFinalT? =
		getFunc(dl!, f: "CCCryptorFinal")
	fileprivate static let CCCryptorRelease: CCCryptorReleaseT? =
		getFunc(dl!, f: "CCCryptorRelease")

	open class GCM {

		open static func crypt(_ opMode: OpMode, algorithm: Algorithm, data: Data,
		                         key: Data, iv: Data,
		                         aData: Data, tagLength: Int) throws -> (Data, Data) {
			var result = Data(count: data.count)
			var tagLength_ = tagLength
			var tag = Data(count: tagLength)
            let status = result.withUnsafeMutableBytes {
                (resultBytes: UnsafeMutablePointer<UInt8>) -> CCCryptorStatus in
                return tag.withUnsafeMutableBytes({ (tagBytes: UnsafeMutablePointer<UInt8>) -> CCCryptorStatus in
                    return CCCryptorGCM!(opMode.rawValue, algorithm.rawValue,
                                         (key as NSData).bytes, key.count, (iv as NSData).bytes, iv.count,
                                         (aData as NSData).bytes, aData.count,
                                         (data as NSData).bytes, data.count,
                                         resultBytes, tagBytes, &tagLength_)
                })
            }
			guard status == noErr else { throw CCError(status) }

			tag.count = tagLength_
			return (result, tag)
		}

		open static func available() -> Bool {
			if CCCryptorGCM != nil {
				return true
			}
			return false
		}

		fileprivate typealias CCCryptorGCMT = @convention(c) (_ op: CCOperation, _ alg: CCAlgorithm,
			_ key: UnsafeRawPointer, _ keyLength: Int,
			_ iv: UnsafeRawPointer, _ ivLen: Int,
			_ aData: UnsafeRawPointer, _ aDataLen: Int,
			_ dataIn: UnsafeRawPointer, _ dataInLength: Int,
			_ dataOut: UnsafeMutableRawPointer,
			_ tag: UnsafeRawPointer, _ tagLength: UnsafeMutablePointer<Int>) -> CCCryptorStatus
		fileprivate static let CCCryptorGCM: CCCryptorGCMT? = getFunc(dl!, f: "CCCryptorGCM")

	}

	open class CCM {

		open static func crypt(_ opMode: OpMode, algorithm: Algorithm, data: Data,
		                         key: Data, iv: Data,
		                         aData: Data, tagLength: Int) throws -> (Data, Data) {
			var cryptor: CCCryptorRef? = nil
			var status = CCCryptorCreateWithMode!(
				opMode.rawValue, AuthBlockMode.ccm.rawValue,
				algorithm.rawValue, Padding.noPadding.rawValue,
				nil, (key as NSData).bytes, key.count, nil, 0,
				0, CCModeOptions(), &cryptor)
			guard status == noErr else { throw CCError(status) }
			defer { _ = CCCryptorRelease!(cryptor!) }

			status = CCCryptorAddParameter!(cryptor!,
				Parameter.dataSize.rawValue, nil, data.count)
			guard status == noErr else { throw CCError(status) }

			status = CCCryptorAddParameter!(cryptor!,
				Parameter.macSize.rawValue, nil, tagLength)
			guard status == noErr else { throw CCError(status) }

			status = CCCryptorAddParameter!(cryptor!,
				Parameter.iv.rawValue, (iv as NSData).bytes, iv.count)
			guard status == noErr else { throw CCError(status) }

			status = CCCryptorAddParameter!(cryptor!,
				Parameter.authData.rawValue, (aData as NSData).bytes, aData.count)
			guard status == noErr else { throw CCError(status) }

			var result = Data(count: data.count)

			var updateLen: size_t = 0
            status = result.withUnsafeMutableBytes({ (resultBytes: UnsafeMutablePointer<UInt8>) -> CCCryptorStatus in
                return CCCryptorUpdate!(
                    cryptor!, (data as NSData).bytes, data.count,
                    resultBytes, result.count,
                    &updateLen)
            })
			guard status == noErr else { throw CCError(status) }

			var finalLen: size_t = 0
            status = result.withUnsafeMutableBytes({ (resultBytes: UnsafeMutablePointer<UInt8>) -> CCCryptorStatus in
                return CCCryptorFinal!(cryptor!, resultBytes + updateLen,
                                       result.count - updateLen,
                                       &finalLen)
            })
			guard status == noErr else { throw CCError(status) }

			result.count = updateLen + finalLen

			var tagLength_ = tagLength
			var tag = Data(count: tagLength)
            status = tag.withUnsafeMutableBytes({ (tagBytes: UnsafeMutablePointer<UInt8>) -> CCCryptorStatus in
                return CCCryptorGetParameter!(cryptor!, Parameter.authTag.rawValue,
                                              tagBytes, &tagLength_)
            })
			guard status == noErr else { throw CCError(status) }

			tag.count = tagLength_

			return (result, tag)
		}

		open static func available() -> Bool {
			if CCCryptorAddParameter != nil &&
				CCCryptorGetParameter != nil {
				return true
			}
			return false
		}

		fileprivate typealias CCParameter = UInt32
		fileprivate enum Parameter: CCParameter {
			case iv, authData, macSize, dataSize, authTag
		}
		fileprivate typealias CCCryptorAddParameterT = @convention(c) (_ cryptorRef: CCCryptorRef,
			_ parameter: CCParameter,
			_ data: UnsafeRawPointer?, _ dataLength: size_t) -> CCCryptorStatus
		fileprivate static let CCCryptorAddParameter: CCCryptorAddParameterT? =
			getFunc(dl!, f: "CCCryptorAddParameter")

		fileprivate typealias CCCryptorGetParameterT = @convention(c) (_ cryptorRef: CCCryptorRef,
			_ parameter: CCParameter,
			_ data: UnsafeRawPointer, _ dataLength: UnsafeMutablePointer<size_t>) -> CCCryptorStatus
		fileprivate static let CCCryptorGetParameter: CCCryptorGetParameterT? =
			getFunc(dl!, f: "CCCryptorGetParameter")
	}

	open class RSA {

		public typealias CCAsymmetricPadding = UInt32

		public enum AsymmetricPadding: CCAsymmetricPadding {
			case pkcs1 = 1001
			case oaep = 1002
		}

		public enum AsymmetricSAPadding: UInt32 {
			case pkcs15 = 1001
			case pss = 1002
		}

		open static func generateKeyPair(_ keySize: Int = 4096) throws -> (Data, Data) {
			var privateKey: CCRSACryptorRef? = nil
			var publicKey: CCRSACryptorRef? = nil
			let status = CCRSACryptorGeneratePair!(
				keySize,
				65537,
				&publicKey,
				&privateKey)
			guard status == noErr else { throw CCError(status) }

			defer {
				CCRSACryptorRelease!(privateKey!)
				CCRSACryptorRelease!(publicKey!)
			}

			let privDERKey = try exportToDERKey(privateKey!)
			let pubDERKey = try exportToDERKey(publicKey!)

			return (privDERKey, pubDERKey)
		}

		open static func encrypt(_ data: Data, derKey: Data, tag: Data, padding: AsymmetricPadding,
		                           digest: DigestAlgorithm) throws -> Data {
			let key = try importFromDERKey(derKey)
			defer { CCRSACryptorRelease!(key) }

			var bufferSize = getKeySize(key)
			var buffer = Data(count: bufferSize)

            let status = buffer.withUnsafeMutableBytes {
                (bufferBytes: UnsafeMutablePointer<UInt8>) -> CCCryptorStatus in
                return CCRSACryptorEncrypt!(
                    key,
                    padding.rawValue,
                    (data as NSData).bytes,
                    data.count,
                    bufferBytes,
                    &bufferSize,
                    (tag as NSData).bytes, tag.count,
                    digest.rawValue)
            }
			guard status == noErr else { throw CCError(status) }

			buffer.count = bufferSize

			return buffer
		}

		open static func decrypt(_ data: Data, derKey: Data, tag: Data, padding: AsymmetricPadding,
		                           digest: DigestAlgorithm) throws -> (Data, Int) {
			let key = try importFromDERKey(derKey)
			defer { CCRSACryptorRelease!(key) }

			let blockSize = getKeySize(key)

			var bufferSize = blockSize
			var buffer = Data(count: bufferSize)

            let status = buffer.withUnsafeMutableBytes {
                (bufferBytes: UnsafeMutablePointer<UInt8>) -> CCCryptorStatus in
                return CCRSACryptorDecrypt!(
                    key,
                    padding.rawValue,
                    (data as NSData).bytes,
                    bufferSize,
                    bufferBytes,
                    &bufferSize,
                    (tag as NSData).bytes, tag.count,
                    digest.rawValue)
            }
			guard status == noErr else { throw CCError(status) }
			buffer.count = bufferSize

			return (buffer, blockSize)
		}

		fileprivate static func importFromDERKey(_ derKey: Data) throws -> CCRSACryptorRef {
			var key: CCRSACryptorRef? = nil
			let status = CCRSACryptorImport!(
				(derKey as NSData).bytes,
				derKey.count,
				&key)
			guard status == noErr else { throw CCError(status) }

			return key!
		}

		fileprivate static func exportToDERKey(_ key: CCRSACryptorRef) throws -> Data {
			var derKeyLength = 8192
			var derKey = Data(count: derKeyLength)
            let status = derKey.withUnsafeMutableBytes {
                (derKeyBytes: UnsafeMutablePointer<UInt8>) -> CCCryptorStatus in
                return CCRSACryptorExport!(key, derKeyBytes, &derKeyLength)
            }
			guard status == noErr else { throw CCError(status) }

			derKey.count = derKeyLength
			return derKey
		}

		fileprivate static func getKeyType(_ key: CCRSACryptorRef) -> KeyType {
			return KeyType(rawValue: CCRSAGetKeyType!(key))!
		}

		fileprivate static func getKeySize(_ key: CCRSACryptorRef) -> Int {
			return Int(CCRSAGetKeySize!(key)/8)
		}

		open static func sign(_ message: Data, derKey: Data, padding: AsymmetricSAPadding,
		                        digest: DigestAlgorithm, saltLen: Int) throws -> Data {
			let key = try importFromDERKey(derKey)
			defer { CCRSACryptorRelease!(key) }
			guard getKeyType(key) == .privateKey else { throw CCError(.paramError) }

			let keySize = getKeySize(key)

			switch padding {
			case .pkcs15:
				let hash = CC.digest(message, alg: digest)
				var signedDataLength = keySize
				var signedData = Data(count:signedDataLength)
                let status = signedData.withUnsafeMutableBytes({
                    (signedDataBytes: UnsafeMutablePointer<UInt8>) -> CCCryptorStatus in
                    return CCRSACryptorSign!(
                        key,
                        AsymmetricPadding.pkcs1.rawValue,
                        (hash as NSData).bytes, hash.count,
                        digest.rawValue, 0 /*unused*/,
                        signedDataBytes, &signedDataLength)
                })
				guard status == noErr else { throw CCError(status) }

				signedData.count = signedDataLength
				return signedData
			case .pss:
				let encMessage = try add_pss_padding(
					digest,
					saltLength: saltLen,
					keyLength: keySize,
					message: message)
				return try crypt(encMessage, key: key)
			}
		}

		open static func verify(_ message: Data, derKey: Data, padding: AsymmetricSAPadding,
		                          digest: DigestAlgorithm, saltLen: Int,
		                          signedData: Data) throws -> Bool {
			let key = try importFromDERKey(derKey)
			defer { CCRSACryptorRelease!(key) }
			guard getKeyType(key) == .publicKey else { throw CCError(.paramError) }

			let keySize = getKeySize(key)

			switch padding {
			case .pkcs15:
				let hash = CC.digest(message, alg: digest)
				let status = CCRSACryptorVerify!(
					key,
					padding.rawValue,
					(hash as NSData).bytes, hash.count,
					digest.rawValue, 0 /*unused*/,
					(signedData as NSData).bytes, signedData.count)
				let kCCNotVerified: CCCryptorStatus = -4306
				if status == kCCNotVerified {
					return false
				}
				guard status == noErr else { throw CCError(status) }
				return true
			case .pss:
				let encoded = try crypt(signedData, key:key)
				return try verify_pss_padding(
					digest,
					saltLength: saltLen,
					keyLength: keySize,
					message: message,
					encMessage: encoded)
			}
		}

		fileprivate static func crypt(_ data: Data, key: CCRSACryptorRef) throws -> Data {
			var outLength = data.count
			var out = Data(count: outLength)
            let status = out.withUnsafeMutableBytes { (outBytes: UnsafeMutablePointer<UInt8>) -> CCCryptorStatus in
                return CCRSACryptorCrypt!(
                        key,
                        (data as NSData).bytes, data.count,
                        outBytes, &outLength)
            }
			guard status == noErr else { throw CCError(status) }
			out.count = outLength

			return out
		}

		fileprivate static func mgf1(_ digest: DigestAlgorithm,
		                         seed: Data, maskLength: Int) -> Data {
			var tseed = seed
            tseed.append(contentsOf: [0,0,0,0] as [UInt8])

			var interval = maskLength / digest.length
			if  maskLength % digest.length != 0 {
				interval += 1
			}

			func pack(_ n: Int) -> [UInt8] {
				return [
					UInt8(n>>24 & 0xff),
					UInt8(n>>16 & 0xff),
					UInt8(n>>8 & 0xff),
					UInt8(n>>0 & 0xff)
				]
			}

			var mask = Data()
			for counter in 0 ..< interval {
				tseed.replaceSubrange((tseed.count - 4) ..< tseed.count, with: pack(counter))
				mask.append(CC.digest(tseed, alg: digest))
			}
			mask.count = maskLength
			return mask
		}

		fileprivate static func xorData(_ data1: Data, _ data2: Data) -> Data {
			precondition(data1.count == data2.count)

            var ret = Data(count: data1.count)
            ret.withUnsafeMutableBytes { (r: UnsafeMutablePointer<UInt8>) -> Void in
                let bytes1 = (data1 as NSData).bytes.bindMemory(to: UInt8.self, capacity: data1.count)
                let bytes2 = (data2 as NSData).bytes.bindMemory(to: UInt8.self, capacity: data2.count)
                for i in 0 ..< ret.count {
                    r[i] = bytes1[i] ^ bytes2[i]
                }
            }
			return ret
		}

		fileprivate static func add_pss_padding(_ digest: DigestAlgorithm,
		                                   saltLength: Int,
		                                   keyLength: Int,
		                                   message: Data) throws -> Data {

			if keyLength < 16 || saltLength < 0 {
				throw CCError(.paramError)
			}

			// The maximal bit size of a non-negative integer is one less than the bit
			// size of the key since the first bit is used to store sign
			let emBits = keyLength * 8  - 1
			var emLength = emBits / 8
			if emBits % 8 != 0 {
				emLength += 1
			}

			let hash = CC.digest(message, alg: digest)

			if emLength < hash.count + saltLength + 2 {
				throw CCError(.paramError)
			}

			let salt = CC.generateRandom(saltLength)

			var mPrime = Data(count: 8)
			mPrime.append(hash)
			mPrime.append(salt)
			let mPrimeHash = CC.digest(mPrime, alg: digest)

			let padding = Data(count: emLength - saltLength - hash.count - 2)
			var db = padding
			db.append([0x01] as [UInt8], count: 1)
			db.append(salt)
			let dbMask = mgf1(digest, seed: mPrimeHash, maskLength: emLength - hash.count - 1)
			var maskedDB = xorData(db, dbMask)

			let zeroBits = 8 * emLength - emBits
            maskedDB.withUnsafeMutableBytes { (mMaskedDb: UnsafeMutablePointer<UInt8>) -> Void in
                mMaskedDb[0] &= UInt8(0xff >> zeroBits)
            }

			var ret = maskedDB
			ret.append(mPrimeHash)
			ret.append([0xBC] as [UInt8], count: 1)
			return ret
		}

		fileprivate static func verify_pss_padding(_ digest: DigestAlgorithm,
		                                      saltLength: Int, keyLength: Int,
		                                      message: Data, encMessage: Data) throws -> Bool {
			if keyLength < 16 || saltLength < 0 {
				throw CCError(.paramError)
			}

			guard encMessage.count > 0 else {
				return false
			}

			let emBits = keyLength * 8  - 1
			var emLength = emBits / 8
			if emBits % 8 != 0 {
				emLength += 1
			}

			let hash = CC.digest(message, alg: digest)

			if emLength < hash.count + saltLength + 2 {
				return false
			}
			if encMessage.bytesView[encMessage.count-1] != 0xBC {
				return false
			}
			let zeroBits = 8 * emLength - emBits
			let zeroBitsM = 8 - zeroBits
			let maskedDBLength = emLength - hash.count - 1
			let maskedDB = encMessage.subdata(in: 0..<maskedDBLength)
			if Int(maskedDB.bytesView[0]) >> zeroBitsM != 0 {
				return false
			}
			let mPrimeHash = encMessage.subdata(in: maskedDBLength ..< maskedDBLength + hash.count)
			let dbMask = mgf1(digest, seed: mPrimeHash, maskLength: emLength - hash.count - 1)
			var db = xorData(maskedDB, dbMask)
            db.withUnsafeMutableBytes { (mDb: UnsafeMutablePointer<UInt8>) -> Void in
                mDb[0] &= UInt8(0xff >> zeroBits)
            }

			let zeroLength = emLength - hash.count - saltLength - 2
			let zeroString = Data(count:zeroLength)
			if db.subdata(in: 0 ..< zeroLength) != zeroString {
				return false
			}
			if db.bytesView[zeroLength] != 0x01 {
				return false
			}
			let salt = db.subdata(in: (db.count - saltLength) ..< db.count)
			var mPrime = Data(count:8)
			mPrime.append(hash)
			mPrime.append(salt)
			let mPrimeHash2 = CC.digest(mPrime, alg: digest)
			if mPrimeHash != mPrimeHash2 {
				return false
			}
			return true
		}


		open static func available() -> Bool {
			return CCRSACryptorGeneratePair != nil &&
				CCRSACryptorRelease != nil &&
				CCRSAGetKeyType != nil &&
				CCRSAGetKeySize != nil &&
				CCRSACryptorEncrypt != nil &&
				CCRSACryptorDecrypt != nil &&
				CCRSACryptorExport != nil &&
				CCRSACryptorImport != nil &&
				CCRSACryptorSign != nil &&
				CCRSACryptorVerify != nil &&
				CCRSACryptorCrypt != nil
		}

		fileprivate typealias CCRSACryptorRef = UnsafeRawPointer
		fileprivate typealias CCRSAKeyType = UInt32
		fileprivate enum KeyType: CCRSAKeyType {
			case publicKey = 0, privateKey
			case blankPublicKey = 97, blankPrivateKey
			case badKey = 99
		}

		fileprivate typealias CCRSACryptorGeneratePairT = @convention(c) (
			_ keySize: Int,
			_ e: UInt32,
			_ publicKey: UnsafeMutablePointer<CCRSACryptorRef?>,
			_ privateKey: UnsafeMutablePointer<CCRSACryptorRef?>) -> CCCryptorStatus
		fileprivate static let CCRSACryptorGeneratePair: CCRSACryptorGeneratePairT? =
			getFunc(CC.dl!, f: "CCRSACryptorGeneratePair")

		fileprivate typealias CCRSACryptorReleaseT = @convention(c) (CCRSACryptorRef) -> Void
		fileprivate static let CCRSACryptorRelease: CCRSACryptorReleaseT? =
			getFunc(dl!, f: "CCRSACryptorRelease")

		fileprivate typealias CCRSAGetKeyTypeT = @convention(c) (CCRSACryptorRef) -> CCRSAKeyType
		fileprivate static let CCRSAGetKeyType: CCRSAGetKeyTypeT? = getFunc(dl!, f: "CCRSAGetKeyType")

		fileprivate typealias CCRSAGetKeySizeT = @convention(c) (CCRSACryptorRef) -> Int32
		fileprivate static let CCRSAGetKeySize: CCRSAGetKeySizeT? = getFunc(dl!, f: "CCRSAGetKeySize")

		fileprivate typealias CCRSACryptorEncryptT = @convention(c) (
			_ publicKey: CCRSACryptorRef,
			_ padding: CCAsymmetricPadding,
			_ plainText: UnsafeRawPointer,
			_ plainTextLen: Int,
			_ cipherText: UnsafeMutableRawPointer,
			_ cipherTextLen: UnsafeMutablePointer<Int>,
			_ tagData: UnsafeRawPointer,
			_ tagDataLen: Int,
			_ digestType: CCDigestAlgorithm) -> CCCryptorStatus
		fileprivate static let CCRSACryptorEncrypt: CCRSACryptorEncryptT? =
			getFunc(dl!, f: "CCRSACryptorEncrypt")

		fileprivate typealias CCRSACryptorDecryptT = @convention (c) (
			_ privateKey: CCRSACryptorRef,
			_ padding: CCAsymmetricPadding,
			_ cipherText: UnsafeRawPointer,
			_ cipherTextLen: Int,
			_ plainText: UnsafeMutableRawPointer,
			_ plainTextLen: UnsafeMutablePointer<Int>,
			_ tagData: UnsafeRawPointer,
			_ tagDataLen: Int,
			_ digestType: CCDigestAlgorithm) -> CCCryptorStatus
		fileprivate static let CCRSACryptorDecrypt: CCRSACryptorDecryptT? =
			getFunc(dl!, f: "CCRSACryptorDecrypt")

		fileprivate typealias CCRSACryptorExportT = @convention(c) (
			_ key: CCRSACryptorRef,
			_ out: UnsafeMutableRawPointer,
			_ outLen: UnsafeMutablePointer<Int>) -> CCCryptorStatus
		fileprivate static let CCRSACryptorExport: CCRSACryptorExportT? =
			getFunc(dl!, f: "CCRSACryptorExport")

		fileprivate typealias CCRSACryptorImportT = @convention(c) (
			_ keyPackage: UnsafeRawPointer,
			_ keyPackageLen: Int,
			_ key: UnsafeMutablePointer<CCRSACryptorRef?>) -> CCCryptorStatus
		fileprivate static let CCRSACryptorImport: CCRSACryptorImportT? =
			getFunc(dl!, f: "CCRSACryptorImport")

		fileprivate typealias CCRSACryptorSignT = @convention(c) (
			_ privateKey: CCRSACryptorRef,
			_ padding: CCAsymmetricPadding,
			_ hashToSign: UnsafeRawPointer,
			_ hashSignLen: size_t,
			_ digestType: CCDigestAlgorithm,
			_ saltLen: size_t,
			_ signedData: UnsafeMutableRawPointer,
			_ signedDataLen: UnsafeMutablePointer<Int>) -> CCCryptorStatus
		fileprivate static let CCRSACryptorSign: CCRSACryptorSignT? =
			getFunc(dl!, f: "CCRSACryptorSign")

		fileprivate typealias CCRSACryptorVerifyT = @convention(c) (
			_ publicKey: CCRSACryptorRef,
			_ padding: CCAsymmetricPadding,
			_ hash: UnsafeRawPointer,
			_ hashLen: size_t,
			_ digestType: CCDigestAlgorithm,
			_ saltLen: size_t,
			_ signedData: UnsafeRawPointer,
			_ signedDataLen: size_t) -> CCCryptorStatus
		fileprivate static let CCRSACryptorVerify: CCRSACryptorVerifyT? =
			getFunc(dl!, f: "CCRSACryptorVerify")

		fileprivate typealias CCRSACryptorCryptT = @convention(c) (
			_ rsaKey: CCRSACryptorRef,
			_ data: UnsafeRawPointer, _ dataLength: size_t,
			_ out: UnsafeMutableRawPointer,
			_ outLength: UnsafeMutablePointer<size_t>) -> CCCryptorStatus
		fileprivate static let CCRSACryptorCrypt: CCRSACryptorCryptT? =
			getFunc(dl!, f: "CCRSACryptorCrypt")
	}

	open class DH {

		public enum DHParam {
			case rfc3526Group5
		}

		//this is stateful in CommonCrypto too, sry
		open class DH {
			fileprivate var ref: CCDHRef? = nil

			public init(dhParam: DHParam) throws {
				ref = CCDHCreate!(kCCDHRFC3526Group5!)
				guard ref != nil else {
					throw CCError(.paramError)
				}
			}

			open func generateKey() throws -> Data {
				var outputLength = 8192
				var output = Data(count: outputLength)
                let status = output.withUnsafeMutableBytes { (outputBytes: UnsafeMutablePointer<UInt8>) -> CInt in
                    return CCDHGenerateKey!(ref!, outputBytes, &outputLength)
                }
				output.count = outputLength
				guard status != -1 else {
					throw CCError(.paramError)
				}
				return output
			}

			open func computeKey(_ peerKey: Data) throws -> Data {
				var sharedKeyLength = 8192
				var sharedKey = Data(count: sharedKeyLength)
                let status = sharedKey.withUnsafeMutableBytes { (sharedKeyBytes: UnsafeMutablePointer<UInt8>) -> CInt in
                    return CCDHComputeKey!(
                        sharedKeyBytes, &sharedKeyLength,
                        (peerKey as NSData).bytes, peerKey.count,
                        ref!)
                }
				sharedKey.count = sharedKeyLength
				guard status == 0 else {
					throw CCError(.paramError)
				}
				return sharedKey
			}

			deinit {
				if ref != nil {
					CCDHRelease!(ref!)
				}
			}
		}


		open static func available() -> Bool {
			return CCDHCreate != nil &&
				CCDHRelease != nil &&
				CCDHGenerateKey != nil &&
				CCDHComputeKey != nil
		}

		fileprivate typealias CCDHParameters = UnsafeRawPointer
		fileprivate typealias CCDHRef = UnsafeRawPointer

		fileprivate typealias kCCDHRFC3526Group5TM = UnsafePointer<CCDHParameters>
		fileprivate static let kCCDHRFC3526Group5M: kCCDHRFC3526Group5TM? =
			getFunc(dl!, f: "kCCDHRFC3526Group5")
		fileprivate static let kCCDHRFC3526Group5 = kCCDHRFC3526Group5M?.pointee

		fileprivate typealias CCDHCreateT = @convention(c) (
			_ dhParameter: CCDHParameters) -> CCDHRef
		fileprivate static let CCDHCreate: CCDHCreateT? = getFunc(dl!, f: "CCDHCreate")

		fileprivate typealias CCDHReleaseT = @convention(c) (
			_ ref: CCDHRef) -> Void
		fileprivate static let CCDHRelease: CCDHReleaseT? = getFunc(dl!, f: "CCDHRelease")

		fileprivate typealias CCDHGenerateKeyT = @convention(c) (
			_ ref: CCDHRef,
			_ output: UnsafeMutableRawPointer, _ outputLength: UnsafeMutablePointer<size_t>) -> CInt
		fileprivate static let CCDHGenerateKey: CCDHGenerateKeyT? = getFunc(dl!, f: "CCDHGenerateKey")

		fileprivate typealias CCDHComputeKeyT = @convention(c) (
			_ sharedKey: UnsafeMutableRawPointer, _ sharedKeyLen: UnsafeMutablePointer<size_t>,
			_ peerPubKey: UnsafeRawPointer, _ peerPubKeyLen: size_t,
			_ ref: CCDHRef) -> CInt
		fileprivate static let CCDHComputeKey: CCDHComputeKeyT? = getFunc(dl!, f: "CCDHComputeKey")
	}

	open class EC {

		open static func generateKeyPair(_ keySize: Int) throws -> (Data, Data) {
			var privKey: CCECCryptorRef? = nil
			var pubKey: CCECCryptorRef? = nil
			let status = CCECCryptorGeneratePair!(
				keySize,
				&pubKey,
				&privKey)
			guard status == noErr else { throw CCError(status) }

			defer {
				CCECCryptorRelease!(privKey!)
				CCECCryptorRelease!(pubKey!)
			}

			let privKeyDER = try exportKey(privKey!, format: .importKeyBinary, type: .keyPrivate)
			let pubKeyDER = try exportKey(pubKey!, format: .importKeyBinary, type: .keyPublic)
			return (privKeyDER, pubKeyDER)
		}

		open static func signHash(_ privateKey: Data, hash: Data) throws -> Data {
			let privKey = try importKey(privateKey, format: .importKeyBinary, keyType: .keyPrivate)
			defer { CCECCryptorRelease!(privKey) }

			var signedDataLength = 4096
			var signedData = Data(count:signedDataLength)
            let status = signedData.withUnsafeMutableBytes {
                (signedDataBytes: UnsafeMutablePointer<UInt8>) -> CCCryptorStatus in
                return CCECCryptorSignHash!(
                    privKey,
                    (hash as NSData).bytes, hash.count,
                    signedDataBytes, &signedDataLength)
            }
			guard status == noErr else { throw CCError(status) }

			signedData.count = signedDataLength
			return signedData
		}

		open static func verifyHash(_ publicKey: Data,
		                              hash: Data,
		                              signedData: Data) throws -> Bool {
			let pubKey = try importKey(publicKey, format: .importKeyBinary, keyType: .keyPublic)
			defer { CCECCryptorRelease!(pubKey) }

			var valid: UInt32 = 0
			let status = CCECCryptorVerifyHash!(
				pubKey,
				(hash as NSData).bytes, hash.count,
				(signedData as NSData).bytes, signedData.count,
				&valid)
			guard status == noErr else { throw CCError(status) }

			return valid != 0
		}

		open static func computeSharedSecret(_ privateKey: Data,
		                                       publicKey: Data) throws -> Data {
			let privKey = try importKey(privateKey, format: .importKeyBinary, keyType: .keyPrivate)
			let pubKey = try importKey(publicKey, format: .importKeyBinary, keyType: .keyPublic)
			defer {
				CCECCryptorRelease!(privKey)
				CCECCryptorRelease!(pubKey)
			}

			var outSize = 8192
			var result = Data(count:outSize)
            let status = result.withUnsafeMutableBytes {
                (resultBytes: UnsafeMutablePointer<UInt8>) -> CCCryptorStatus in
                return CCECCryptorComputeSharedSecret!(privKey, pubKey, resultBytes, &outSize)
            }
			guard status == noErr else { throw CCError(status) }

			result.count = outSize
			return result
		}

		fileprivate static func importKey(_ key: Data, format: KeyExternalFormat,
		                              keyType: KeyType) throws -> CCECCryptorRef {
			var impKey: CCECCryptorRef? = nil
			let status = CCECCryptorImportKey!(format.rawValue,
			                                   (key as NSData).bytes, key.count,
			                                   keyType.rawValue, &impKey)
			guard status == noErr else { throw CCError(status) }

			return impKey!
		}

		fileprivate static func exportKey(_ key: CCECCryptorRef, format: KeyExternalFormat,
		                              type: KeyType) throws -> Data {
			var expKeyLength = 8192
			var expKey = Data(count:expKeyLength)
            let status = expKey.withUnsafeMutableBytes {
                (expKeyBytes: UnsafeMutablePointer<UInt8>) -> CCCryptorStatus in
                return CCECCryptorExportKey!(
                    format.rawValue,
                    expKeyBytes,
                    &expKeyLength,
                    type.rawValue,
                    key)
            }
			guard status == noErr else { throw CCError(status) }

			expKey.count = expKeyLength
			return expKey
		}

		open static func available() -> Bool {
			return CCECCryptorGeneratePair != nil &&
				CCECCryptorImportKey != nil &&
				CCECCryptorExportKey != nil &&
				CCECCryptorRelease != nil &&
				CCECCryptorSignHash != nil &&
				CCECCryptorVerifyHash != nil &&
				CCECCryptorComputeSharedSecret != nil
		}

		fileprivate enum KeyType: CCECKeyType {
			case keyPublic = 0, keyPrivate
			case blankPublicKey = 97, blankPrivateKey
			case badKey = 99
		}
		fileprivate typealias CCECKeyType = UInt32

		fileprivate typealias CCECKeyExternalFormat = UInt32
		fileprivate enum KeyExternalFormat: CCECKeyExternalFormat {
			case importKeyBinary = 0, importKeyDER
		}

		fileprivate typealias CCECCryptorRef = UnsafeRawPointer
		fileprivate typealias CCECCryptorGeneratePairT = @convention(c) (
			_ keySize: size_t ,
			_ publicKey: UnsafeMutablePointer<CCECCryptorRef?>,
			_ privateKey: UnsafeMutablePointer<CCECCryptorRef?>) -> CCCryptorStatus
		fileprivate static let CCECCryptorGeneratePair: CCECCryptorGeneratePairT? =
			getFunc(dl!, f: "CCECCryptorGeneratePair")

		fileprivate typealias CCECCryptorImportKeyT = @convention(c) (
			_ format: CCECKeyExternalFormat,
			_ keyPackage: UnsafeRawPointer, _ keyPackageLen: size_t,
			_ keyType: CCECKeyType, _ key: UnsafeMutablePointer<CCECCryptorRef?>) -> CCCryptorStatus
		fileprivate static let CCECCryptorImportKey: CCECCryptorImportKeyT? =
			getFunc(dl!, f: "CCECCryptorImportKey")

		fileprivate typealias CCECCryptorExportKeyT = @convention(c) (
			_ format: CCECKeyExternalFormat,
			_ keyPackage: UnsafeRawPointer,
			_ keyPackageLen: UnsafePointer<size_t>,
			_ keyType: CCECKeyType, _ key: CCECCryptorRef) -> CCCryptorStatus
		fileprivate static let CCECCryptorExportKey: CCECCryptorExportKeyT? =
			getFunc(dl!, f: "CCECCryptorExportKey")

		fileprivate typealias CCECCryptorReleaseT = @convention(c) (
			_ key: CCECCryptorRef) -> Void
		fileprivate static let CCECCryptorRelease: CCECCryptorReleaseT? =
			getFunc(dl!, f: "CCECCryptorRelease")

		fileprivate typealias CCECCryptorSignHashT = @convention(c)(
			_ privateKey: CCECCryptorRef,
			_ hashToSign: UnsafeRawPointer,
			_ hashSignLen: size_t,
			_ signedData: UnsafeMutableRawPointer,
			_ signedDataLen: UnsafeMutablePointer<size_t>) -> CCCryptorStatus
		fileprivate static let CCECCryptorSignHash: CCECCryptorSignHashT? =
			getFunc(dl!, f: "CCECCryptorSignHash")

		fileprivate typealias CCECCryptorVerifyHashT = @convention(c)(
			_ publicKey: CCECCryptorRef,
			_ hash: UnsafeRawPointer, _ hashLen: size_t,
			_ signedData: UnsafeRawPointer, _ signedDataLen: size_t,
			_ valid: UnsafeMutablePointer<UInt32>) -> CCCryptorStatus
		fileprivate static let CCECCryptorVerifyHash: CCECCryptorVerifyHashT? =
			getFunc(dl!, f: "CCECCryptorVerifyHash")

		fileprivate typealias CCECCryptorComputeSharedSecretT = @convention(c)(
			_ privateKey: CCECCryptorRef,
			_ publicKey: CCECCryptorRef,
			_ out: UnsafeMutableRawPointer,
			_ outLen: UnsafeMutablePointer<size_t>) -> CCCryptorStatus
		fileprivate static let CCECCryptorComputeSharedSecret: CCECCryptorComputeSharedSecretT? =
			getFunc(dl!, f: "CCECCryptorComputeSharedSecret")
	}

	open class CRC {

		public typealias CNcrc = UInt32
		public enum Mode: CNcrc {
			case crc8 = 10,
			crc8ICODE = 11,
			crc8ITU = 12,
			crc8ROHC = 13,
			crc8WCDMA = 14,
			crc16 = 20,
			crc16CCITTTrue = 21,
			crc16CCITTFalse = 22,
			crc16USB = 23,
			crc16XMODEM = 24,
			crc16DECTR = 25,
			crc16DECTX = 26,
			crc16ICODE = 27,
			crc16VERIFONE = 28,
			crc16A = 29,
			crc16B = 30,
			crc16Fletcher = 31,
			crc32Adler = 40,
			crc32 = 41,
			crc32CASTAGNOLI = 42,
			crc32BZIP2 = 43,
			crc32MPEG2 = 44,
			crc32POSIX = 45,
			crc32XFER = 46,
			crc64ECMA182 = 60
		}

		open static func crc(_ input: Data, mode: Mode) throws -> UInt64 {
			var result: UInt64 = 0
			let status = CNCRC!(
				mode.rawValue,
				(input as NSData).bytes, input.count,
				&result)
			guard status == noErr else {
				throw CCError(status)
			}
			return result
		}

		open static func available() -> Bool {
			return CNCRC != nil
		}

		fileprivate typealias CNCRCT = @convention(c) (
			_ algorithm: CNcrc,
			_ input: UnsafeRawPointer, _ inputLen: size_t,
			_ result: UnsafeMutablePointer<UInt64>) -> CCCryptorStatus
		fileprivate static let CNCRC: CNCRCT? = getFunc(dl!, f: "CNCRC")
	}

	open class CMAC {

		open static func AESCMAC(_ data: Data, key: Data) -> Data {
			var result = Data(count: 16)
            result.withUnsafeMutableBytes { (resultBytes: UnsafeMutablePointer<UInt8>) -> Void in
                CCAESCmac!((key as NSData).bytes,
                           (data as NSData).bytes, data.count,
                           resultBytes)
            }
			return result
		}

		open static func available() -> Bool {
			return CCAESCmac != nil
		}

		fileprivate typealias CCAESCmacT = @convention(c) (
			_ key: UnsafeRawPointer,
			_ data: UnsafeRawPointer, _ dataLen: size_t,
			_ macOut: UnsafeMutableRawPointer) -> Void
		fileprivate static let CCAESCmac: CCAESCmacT? = getFunc(dl!, f: "CCAESCmac")
	}

	open class KeyDerivation {

		public typealias CCPseudoRandomAlgorithm = UInt32
		public enum PRFAlg: CCPseudoRandomAlgorithm {
			case sha1 = 1, sha224, sha256, sha384, sha512
			var cc: CC.HMACAlg {
				switch self {
				case .sha1: return .sha1
				case .sha224: return .sha224
				case .sha256: return .sha256
				case .sha384: return .sha384
				case .sha512: return .sha512
				}
			}
		}

		open static func PBKDF2(_ password: String, salt: Data,
		                         prf: PRFAlg, rounds: UInt32) throws -> Data {

			var result = Data(count:prf.cc.digestLength)
			let passwData = password.data(using: String.Encoding.utf8)!
            let status = result.withUnsafeMutableBytes {
                (passwDataBytes: UnsafeMutablePointer<UInt8>) -> CCCryptorStatus in
                return CCKeyDerivationPBKDF!(PBKDFAlgorithm.pbkdf2.rawValue,
                                             (passwData as NSData).bytes, passwData.count,
                                             (salt as NSData).bytes, salt.count,
                                             prf.rawValue, rounds,
                                             passwDataBytes, result.count)
            }
			guard status == noErr else { throw CCError(status) }

			return result
		}

		open static func available() -> Bool {
			return CCKeyDerivationPBKDF != nil
		}

		fileprivate typealias CCPBKDFAlgorithm = UInt32
		fileprivate enum PBKDFAlgorithm: CCPBKDFAlgorithm {
			case pbkdf2 = 2
		}

		fileprivate typealias CCKeyDerivationPBKDFT = @convention(c) (
			_ algorithm: CCPBKDFAlgorithm,
			_ password: UnsafeRawPointer, _ passwordLen: size_t,
			_ salt: UnsafeRawPointer, _ saltLen: size_t,
			_ prf: CCPseudoRandomAlgorithm, _ rounds: uint,
			_ derivedKey: UnsafeMutableRawPointer, _ derivedKeyLen: size_t) -> CCCryptorStatus
		fileprivate static let CCKeyDerivationPBKDF: CCKeyDerivationPBKDFT? =
			getFunc(dl!, f: "CCKeyDerivationPBKDF")
	}

	open class KeyWrap {

		fileprivate static let rfc3394IVData: [UInt8] = [0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6]
		open static let rfc3394IV = Data(bytes: UnsafePointer<UInt8>(rfc3394IVData), count:rfc3394IVData.count)

		open static func SymmetricKeyWrap(_ iv: Data,
		                                    kek: Data,
		                                    rawKey: Data) throws -> Data {
			let alg = WrapAlg.aes.rawValue
			var wrappedKeyLength = CCSymmetricWrappedSize!(alg, rawKey.count)
			var wrappedKey = Data(count:wrappedKeyLength)
            let status = wrappedKey.withUnsafeMutableBytes {
                (wrappedKeyBytes: UnsafeMutablePointer<UInt8>) -> CCCryptorStatus in
                return CCSymmetricKeyWrap!(
                    alg,
                    (iv as NSData).bytes, iv.count,
                    (kek as NSData).bytes, kek.count,
                    (rawKey as NSData).bytes, rawKey.count,
                    wrappedKeyBytes, &wrappedKeyLength)
            }
			guard status == noErr else { throw CCError(status) }

			wrappedKey.count = wrappedKeyLength
			return wrappedKey
		}

		open static func SymmetricKeyUnwrap(_ iv: Data,
		                                      kek: Data,
		                                      wrappedKey: Data) throws -> Data {
			let alg = WrapAlg.aes.rawValue
			var rawKeyLength = CCSymmetricUnwrappedSize!(alg, wrappedKey.count)
			var rawKey = Data(count:rawKeyLength)
            let status = rawKey.withUnsafeMutableBytes {
                (rawKeyBytes: UnsafeMutablePointer<UInt8>) -> CCCryptorStatus in
                return CCSymmetricKeyUnwrap!(
                    alg,
                    (iv as NSData).bytes, iv.count,
                    (kek as NSData).bytes, kek.count,
                    (wrappedKey as NSData).bytes, wrappedKey.count,
                    rawKeyBytes, &rawKeyLength)
            }
			guard status == noErr else { throw CCError(status) }

			rawKey.count = rawKeyLength
			return rawKey
		}

		open static func available() -> Bool {
			return CCSymmetricKeyWrap != nil &&
				CCSymmetricKeyUnwrap != nil &&
				CCSymmetricWrappedSize != nil &&
				CCSymmetricUnwrappedSize != nil
		}

		fileprivate enum WrapAlg: CCWrappingAlgorithm {
			case aes = 1
		}
		fileprivate typealias CCWrappingAlgorithm = UInt32

		fileprivate typealias CCSymmetricKeyWrapT = @convention(c) (
			_ algorithm: CCWrappingAlgorithm,
			_ iv: UnsafeRawPointer, _ ivLen: size_t,
			_ kek: UnsafeRawPointer, _ kekLen: size_t,
			_ rawKey: UnsafeRawPointer, _ rawKeyLen: size_t,
			_ wrappedKey: UnsafeMutableRawPointer,
			_ wrappedKeyLen: UnsafePointer<size_t>) -> CCCryptorStatus
		fileprivate static let CCSymmetricKeyWrap: CCSymmetricKeyWrapT? = getFunc(dl!, f: "CCSymmetricKeyWrap")

		fileprivate typealias CCSymmetricKeyUnwrapT = @convention(c) (
			_ algorithm: CCWrappingAlgorithm,
			_ iv: UnsafeRawPointer, _ ivLen: size_t,
			_ kek: UnsafeRawPointer, _ kekLen: size_t,
			_ wrappedKey: UnsafeRawPointer, _ wrappedKeyLen: size_t,
			_ rawKey: UnsafeMutableRawPointer,
			_ rawKeyLen: UnsafePointer<size_t>) -> CCCryptorStatus
		fileprivate static let CCSymmetricKeyUnwrap: CCSymmetricKeyUnwrapT? =
			getFunc(dl!, f: "CCSymmetricKeyUnwrap")

		fileprivate typealias CCSymmetricWrappedSizeT = @convention(c) (
			_ algorithm: CCWrappingAlgorithm,
			_ rawKeyLen: size_t) -> size_t
		fileprivate static let CCSymmetricWrappedSize: CCSymmetricWrappedSizeT? =
			getFunc(dl!, f: "CCSymmetricWrappedSize")

		fileprivate typealias CCSymmetricUnwrappedSizeT = @convention(c) (
			_ algorithm: CCWrappingAlgorithm,
			_ wrappedKeyLen: size_t) -> size_t
		fileprivate static let CCSymmetricUnwrappedSize: CCSymmetricUnwrappedSizeT? =
			getFunc(dl!, f: "CCSymmetricUnwrappedSize")

	}

}

private func getFunc<T>(_ from: UnsafeMutableRawPointer, f: String) -> T? {
	let sym = dlsym(from, f)
	guard sym != nil else {
		return nil
	}
	return unsafeBitCast(sym, to: T.self)
}

extension Data {
	/// Create hexadecimal string representation of Data object.
	///
	/// - returns: String representation of this Data object.

	public func hexadecimalString() -> String {
		var hexstr = String()
        self.withUnsafeBytes { (data: UnsafePointer<UInt8>) -> Void in
            for i in UnsafeBufferPointer<UInt8>(start: data, count: count) {
                hexstr += String(format: "%02X", i)
            }
        }
		return hexstr
	}

	public func arrayOfBytes() -> [UInt8] {
		let count = self.count / MemoryLayout<UInt8>.size
		var bytesArray = [UInt8](repeating: 0, count: count)
		(self as NSData).getBytes(&bytesArray, length:count * MemoryLayout<UInt8>.size)
		return bytesArray
	}

	fileprivate var bytesView: BytesView { return BytesView(self) }

	fileprivate func bytesViewRange(_ range: NSRange) -> BytesView {
		return BytesView(self, range: range)
	}

	fileprivate struct BytesView: Collection {
		// The view retains the Data. That's on purpose.
		// Data doesn't retain the view, so there's no loop.
		let data: Data
		init(_ data: Data) {
			self.data = data
			self.startIndex = 0
			self.endIndex = data.count
		}

		init(_ data: Data, range: NSRange ) {
			self.data = data
			self.startIndex = range.location
			self.endIndex = range.location + range.length
		}

		subscript (position: Int) -> UInt8 {
            var value: UInt8 = 0
            data.withUnsafeBytes { (dataBytes: UnsafePointer<UInt8>) -> Void in
                value = UnsafeBufferPointer<UInt8>(start: dataBytes, count: data.count)[position]
            }
            return value
		}
		subscript (bounds: Range<Int>) -> Data {
			return data.subdata(in: bounds)
		}
        fileprivate func formIndex(after i: inout Int) {
            i += 1
        }
        fileprivate func index(after i: Int) -> Int {
            return i + 1
        }
		var startIndex: Int
		var endIndex: Int
		var length: Int { return endIndex - startIndex }
	}
}

extension String {

	/// Create Data from hexadecimal string representation
	///
	/// This takes a hexadecimal representation and creates a Data object. Note, if the string has
	/// any spaces, those are removed. Also if the string started with a '<' or ended with a '>',
	/// those are removed, too. This does no validation of the string to ensure it's a valid
	/// hexadecimal string
	///
	/// The use of `strtoul` inspired by Martin R at http://stackoverflow.com/a/26284562/1271826
	///
	/// - returns: Data represented by this hexadecimal string.
	///            Returns nil if string contains characters outside the 0-9 and a-f range.

	public func dataFromHexadecimalString() -> Data? {
		let trimmedString = self.trimmingCharacters(
			in: CharacterSet(charactersIn: "<> ")).replacingOccurrences(
				of: " ", with: "")

		// make sure the cleaned up string consists solely of hex digits,
		// and that we have even number of them

		let regex = try! NSRegularExpression(pattern: "^[0-9a-f]*$", options: .caseInsensitive)

		let found = regex.firstMatch(in: trimmedString, options: [],
		                                     range: NSRange(location: 0,
												length: trimmedString.characters.count))
		guard found != nil &&
			found?.range.location != NSNotFound &&
			trimmedString.characters.count % 2 == 0 else {
				return nil
		}

		// everything ok, so now let's build Data

		var data = Data(capacity: trimmedString.characters.count / 2)
        var index: String.Index? = trimmedString.startIndex
        
        while let i = index {
            let byteString = trimmedString.substring(with: i ..< trimmedString.index(i, offsetBy: 2))
            let num = UInt8(byteString.withCString { strtoul($0, nil, 16) })
            data.append([num] as [UInt8], count: 1)
            
            index = trimmedString.index(i, offsetBy: 2, limitedBy: trimmedString.endIndex)
            if index == trimmedString.endIndex { break }
        }

		return data
	}
}
