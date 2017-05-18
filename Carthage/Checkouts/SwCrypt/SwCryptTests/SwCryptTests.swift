import XCTest
import SwCrypt

let keyPair = try? SwCryptTest.createKeyPair(2048)

class SwCryptTest: XCTestCase {

    override func setUp() {
        super.setUp()
		self.continueAfterFailure = false
    }

    override func tearDown() {
        super.tearDown()
    }

	static func createKeyPair(_ size: Int) throws -> (Data, Data) {
		return try CC.RSA.generateKeyPair(size)
	}

	func testAvailable() {
		XCTAssert(CC.digestAvailable())
		XCTAssert(CC.randomAvailable())
		XCTAssert(CC.hmacAvailable())
		XCTAssert(CC.cryptorAvailable())
		XCTAssert(CC.RSA.available())
		XCTAssert(CC.GCM.available())
		XCTAssert(CC.available())
	}

	func testDigest() {
		XCTAssert(CC.digestAvailable())
		let testData = "rokafogtacsuka".data(using: String.Encoding.utf8)!
		let sha1 = "9e421ffa8b2c83ac23e96bc9f9302f4a16311037".dataFromHexadecimalString()!
		let sha256 = "ae6ab1cf65971f88b9cd92c2f334d6a99beaf5b40240d4b440fdb4a1231db0f0"
			.dataFromHexadecimalString()!
		let sha384 = ("acf011a346e96364091bd21415a2437273c7f3c84060b21ac19f2eafa1c6cde76467b0b0" +
			"aba99626b18aa3da83e442db").dataFromHexadecimalString()!
		let sha512 = ("016748fad47ddfba4fcd19aacc67ee031dfef40f5e9692c84f8846e520f2a827a4ea5035" +
			"af8a66686c60796a362c30e6c473cfdbb9d86f43312001fc0b660734").dataFromHexadecimalString()!
		let sha224 = "ec92519bb9e82a79097b0dd0618927b3262a70d6f02bd667c413009e"
			.dataFromHexadecimalString()!
		let md5 = "9b43f853613732cfc8531ed6bcbf6d68".dataFromHexadecimalString()!
		XCTAssert(CC.digest(testData, alg: .sha1) == sha1)
		XCTAssert(CC.digest(testData, alg: .sha256) == sha256)
		XCTAssert(CC.digest(testData, alg: .sha384) == sha384)
		XCTAssert(CC.digest(testData, alg: .sha512) == sha512)
		XCTAssert(CC.digest(testData, alg: .sha224) == sha224)
		XCTAssert(CC.digest(testData, alg: .md5) == md5)
	}

	func testRandom() {
		XCTAssert(CC.randomAvailable())
		_ = CC.generateRandom(10)
	}

    func testCreateKeyPair() {
		XCTAssert(keyPair != nil)
	}

	func testUpsert() {
		let (priv, _) = keyPair!
		let privKey = SwKeyConvert.PrivateKey.derToPKCS1PEM(priv)
		XCTAssertNotNil(try? SwKeyStore.upsertKey(privKey, keyTag: "priv",
			options: [kSecAttrAccessible:kSecAttrAccessibleWhenUnlockedThisDeviceOnly]))
		XCTAssertNotNil(try? SwKeyStore.upsertKey(privKey, keyTag: "priv"))
		XCTAssert(try SwKeyStore.getKey("priv") == privKey)
	}

	func testDel() throws {
		let tag = "priv"
		let (priv, _) = keyPair!
		let privKey = SwKeyConvert.PrivateKey.derToPKCS1PEM(priv)
		XCTAssertNotNil(try? SwKeyStore.upsertKey(privKey, keyTag: tag))
		XCTAssertNotNil(try? SwKeyStore.getKey(tag))
		XCTAssertNotNil(try? SwKeyStore.delKey(tag))
		XCTAssertNil(try? SwKeyStore.getKey(tag))
	}

	func encryptKey(_ enc: SwKeyConvert.PrivateKey.EncMode) {
		let pass = "hello"
		let (priv, _) = keyPair!
		let privKey = SwKeyConvert.PrivateKey.derToPKCS1PEM(priv)

		let privEncrypted = try? SwKeyConvert.PrivateKey.encryptPEM(privKey, passphrase: pass, mode: enc)
		XCTAssert(privEncrypted != nil)
		let privDecrypted = try? SwKeyConvert.PrivateKey.decryptPEM(privEncrypted!, passphrase: pass)
		XCTAssert(privDecrypted != nil)
		XCTAssert(privDecrypted == privKey)
	}

	func testEncryptKey() {
		encryptKey(.aes128CBC)
		encryptKey(.aes256CBC)
	}

	func testKeyNotEncrypted() {
		let bundle = Bundle(for: type(of: self))
		let decPEM = bundle.object(forInfoDictionaryKey: "testPrivDecryptedPEM") as! String
		XCTAssertThrowsError(try SwKeyConvert.PrivateKey.decryptPEM(decPEM, passphrase: "hello")) {
			XCTAssert($0 as? SwKeyConvert.SwError == SwKeyConvert.SwError.keyNotEncrypted)
		}
	}

	func testKeyInvalid() {
		let bundle = Bundle(for: type(of: self))
		var decPEM = bundle.object(forInfoDictionaryKey: "testPrivDecryptedPEM") as! String
		decPEM = "a" + decPEM
		XCTAssertThrowsError(try SwKeyConvert.PrivateKey.decryptPEM(decPEM, passphrase: "hello")) {
			XCTAssert($0 as? SwKeyConvert.SwError == SwKeyConvert.SwError.invalidKey)
		}
	}

	func decryptOpenSSLKeys(_ type: String) {
		let bundle = Bundle(for: type(of: self))
		let encPEM = bundle.object(forInfoDictionaryKey: "testPrivEncryptedPEMAES" + type) as! String
		let decPEM = bundle.object(forInfoDictionaryKey: "testPrivDecryptedPEM") as! String
		let d = try? SwKeyConvert.PrivateKey.decryptPEM(encPEM, passphrase: "hello")
		XCTAssert(d != nil)
		XCTAssert(d! == decPEM)
	}

	func decryptOpenSSLKeysBadPassphrase(_ type: String) {
		let bundle = Bundle(for: type(of: self))
		let encPEM = bundle.object(forInfoDictionaryKey: "testPrivEncryptedPEMAES" + type) as! String

		XCTAssertThrowsError(try SwKeyConvert.PrivateKey.decryptPEM(encPEM, passphrase: "nohello")) {
			XCTAssert($0 as? SwKeyConvert.SwError == SwKeyConvert.SwError.badPassphrase)
		}
	}

	func testOpenSSLKeyPair() {
		let bundle = Bundle(for: type(of: self))
		let priv = bundle.object(forInfoDictionaryKey: "testPrivPEM") as! String
		let pub = bundle.object(forInfoDictionaryKey: "testPubPEM") as! String
		let privKey = try? SwKeyConvert.PrivateKey.pemToPKCS1DER(priv)
		XCTAssert(privKey != nil)
		let pubKey = try? SwKeyConvert.PublicKey.pemToPKCS1DER(pub)
		XCTAssert(pubKey != nil)
	}

	func testOpenSSLKeys() {
		decryptOpenSSLKeys("128")
		decryptOpenSSLKeys("256")
		decryptOpenSSLKeysBadPassphrase("128")
		decryptOpenSSLKeysBadPassphrase("256")
	}

	func testEncryptDecryptOAEPSHA256() {
		let (priv, pub) = keyPair!
		let testData = "This is a test string".data(using: String.Encoding.utf8)!

		let e = try? CC.RSA.encrypt(testData, derKey: pub, tag: Data(), padding: .oaep, digest: .sha256)
		XCTAssert(e != nil)
		let d = try? CC.RSA.decrypt(e!, derKey: priv, tag: Data(), padding: .oaep, digest: .sha256)
		XCTAssert(d != nil)
		XCTAssert(testData == d!.0)
	}

	func testEncryptDecryptGCM() {
		let aesKey = CC.generateRandom(32)
		let iv = CC.generateRandom(12)
		let testData = "This is a test string".data(using: String.Encoding.utf8)!

		let e = try? CC.cryptAuth(.encrypt, blockMode: .gcm, algorithm: .aes, data: testData, aData: Data(), key: aesKey, iv: iv, tagLength: 8)
		XCTAssert(e != nil)
		let d = try? CC.cryptAuth(.decrypt, blockMode: .gcm, algorithm: .aes, data: e!, aData: Data(), key: aesKey, iv: iv, tagLength: 8)
		XCTAssert(d != nil)
		XCTAssert(testData == d!)
	}

	func signVerify(_ privKey: Data, pubKey:Data, padding: CC.RSA.AsymmetricSAPadding) {
		let testMessage = "rirararom_vagy_rararirom".data(using: String.Encoding.utf8)!
		let sign = try? CC.RSA.sign(testMessage, derKey: privKey, padding: padding,
		                            digest: .sha256, saltLen: 16)
		XCTAssert(sign != nil)
		let verified = try? CC.RSA.verify(testMessage, derKey: pubKey, padding: padding,
		                                  digest: .sha256, saltLen: 16, signedData: sign!)
		XCTAssert(verified != nil && verified! == true)
	}

	func testSignVerify() {
		let (priv, pub) = keyPair!
		signVerify(priv, pubKey: pub, padding: .pkcs15)
		signVerify(priv, pubKey: pub, padding: .pss)
	}

	func testCCM() {
		let data = "hello".data(using: String.Encoding.utf8)!
		let key = "8B142BB0FA0043C32821BB90A3453884".dataFromHexadecimalString()!
		let iv = "B5863BD2ABBED31DC26C4EDB5A".dataFromHexadecimalString()!
		let aData = "hello".data(using: String.Encoding.utf8)!
		let tagLength = 16
		XCTAssert(CC.CCM.available())

		let enc = try? CC.CCM.crypt(.encrypt, algorithm: .aes, data: data, key: key, iv: iv,
		                            aData: aData, tagLength: tagLength)
		XCTAssert(enc != nil)
		let dec = try? CC.CCM.crypt(.decrypt, algorithm: .aes, data: enc!.0, key: key, iv: iv,
		                            aData: aData, tagLength: tagLength)
		XCTAssert(dec != nil)
		XCTAssert(enc!.1 == dec!.1)
		XCTAssert(dec!.0 == data)
	}

	func testCCMSJCL() {
		let data = "hello".data(using: String.Encoding.utf8)!
		let key = "8B142BB0FA0043C32821BB90A3453884".dataFromHexadecimalString()!
		let iv = "B5863BD2ABBED31DC26C4EDB5A".dataFromHexadecimalString()!
		let aData = "hello".data(using: String.Encoding.utf8)!
		let tagLength = 16
		let sjclCipher = Data(base64Encoded: "VqAna25S22M+yOZz57wCllx7Itql", options: [])!
		XCTAssert(CC.CCM.available())

		let enc = try? CC.cryptAuth(.encrypt, blockMode: .ccm, algorithm: .aes, data: data,
		                            aData: aData, key: key, iv: iv, tagLength: tagLength)
		XCTAssert(enc != nil)
		XCTAssert(enc! == sjclCipher)

		let dec = try? CC.cryptAuth(.decrypt, blockMode: .ccm, algorithm: .aes, data: sjclCipher,
		                            aData: aData, key: key, iv: iv, tagLength: tagLength)
		XCTAssert(dec != nil)
		XCTAssert(dec! == data)
	}

	func testPBKDF2() {
		let password = "password"
		let salt = "salt".data(using: String.Encoding.utf8)!

		XCTAssert(CC.KeyDerivation.available())
		let stretched = try? CC.KeyDerivation.PBKDF2(password, salt: salt, prf: .sha256, rounds: 4096)
		XCTAssert(stretched != nil)
		let t = "c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a"
			.dataFromHexadecimalString()
		XCTAssert(t == stretched!)
	}

	func testKeyWrap() {
		let kek = "000102030405060708090A0B0C0D0E0F".dataFromHexadecimalString()!
		let tkey = "00112233445566778899AABBCCDDEEFF".dataFromHexadecimalString()!
		let wrappedKey = "1FA68B0A8112B447AEF34BD8FB5A7B829D3E862371D2CFE5"
			.dataFromHexadecimalString()!

		XCTAssert(CC.KeyWrap.available())
		let cipher = try? CC.KeyWrap.SymmetricKeyWrap(CC.KeyWrap.rfc3394IV, kek: kek, rawKey: tkey)
		XCTAssert(cipher != nil)
		XCTAssert(cipher! == wrappedKey)

		let key = try? CC.KeyWrap.SymmetricKeyUnwrap(CC.KeyWrap.rfc3394IV, kek: kek, wrappedKey: cipher!)
		XCTAssert(key != nil)
		XCTAssert(key! == tkey)
	}

	func testECGenkey() {
		XCTAssert(CC.EC.available())

		let keys = try? CC.EC.generateKeyPair(384)
		XCTAssert(keys != nil)
		let keysTooLittle = try? CC.EC.generateKeyPair(128)
		XCTAssert(keysTooLittle == nil)
	}

	func testECSignVerify() {
		let keys = try? CC.EC.generateKeyPair(256)
		XCTAssert(keys != nil)
		let hash = "c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a"
			.dataFromHexadecimalString()!

		let signed = try? CC.EC.signHash(keys!.0, hash: hash)
		XCTAssert(signed != nil)
		let verified = try? CC.EC.verifyHash(keys!.1, hash: hash, signedData: signed!)
		XCTAssert(verified == true)
	}

	func testECSharedSecret() {
		let keys1 = try? CC.EC.generateKeyPair(384)
		XCTAssert(keys1 != nil)
		let keys2 = try? CC.EC.generateKeyPair(384)
		XCTAssert(keys2 != nil)

		let shared1 = try? CC.EC.computeSharedSecret(keys1!.0, publicKey: keys2!.1)
		XCTAssert(shared1 != nil)
		let shared2 = try? CC.EC.computeSharedSecret(keys2!.0, publicKey: keys1!.1)
		XCTAssert(shared2 != nil)
		XCTAssert(shared1! == shared2!)
	}

	func testDH() {
		XCTAssert(CC.DH.available())
		let dh1 = try? CC.DH.DH(dhParam: .rfc3526Group5)
		XCTAssert(dh1 != nil)
		let dh2 = try? CC.DH.DH(dhParam: .rfc3526Group5)
		XCTAssert(dh2 != nil)

		let pub1 = try? dh1!.generateKey()
		XCTAssert(pub1 != nil)
		let pub2 = try? dh2!.generateKey()
		XCTAssert(pub2 != nil)

		let common1 = try? dh1!.computeKey(pub2!)
		XCTAssert(common1 != nil)
		let common2 = try? dh2!.computeKey(pub1!)
		XCTAssert(common2 != nil)
		XCTAssert(common1 == common2)
	}

	func testCRC() {
		XCTAssert(CC.CRC.available())
		let input = "abcdefg".data(using: String.Encoding.utf8)!
		let expectedOutput: UInt64 = 0x312A6AA6
		let output = try? CC.CRC.crc(input, mode: .crc32)
		XCTAssert(output != nil)
		XCTAssert(output == expectedOutput)
	}

	func testCMAC() {
		XCTAssert(CC.CMAC.available())
		let input = "abcdefg".data(using: String.Encoding.utf8)!
		let key = "8B142BB0FA0043C32821BB90A3453884".dataFromHexadecimalString()!
		let expectedOutput = "a7903c21aaa33db4c8ad7b23a947e0bd".dataFromHexadecimalString()!
		let cmac = CC.CMAC.AESCMAC(input, key: key)
		XCTAssert(cmac == expectedOutput)
	}
}
