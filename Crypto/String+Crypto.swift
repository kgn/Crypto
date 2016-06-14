//
//  NSString+Crypto.swift
//  Crypto
//
//  Created by Sam Soffes on 4/21/15.
//  Copyright (c) 2015 Sam Soffes. All rights reserved.
//

import Foundation
import CommonCrypto

extension String {

	// MARK: - Digest

	public var md2: String? {
		return String(digestData: hashData?.md2, length: CC_MD2_DIGEST_LENGTH)
	}

	public var md4: String? {
		return String(digestData: hashData?.md4, length: CC_MD4_DIGEST_LENGTH)
	}

	public var md5: String? {
		return String(digestData: hashData?.md5, length: CC_MD5_DIGEST_LENGTH)
	}
	
	public var sha1: String? {
		return String(digestData: hashData?.sha1, length: CC_SHA1_DIGEST_LENGTH)
	}

	public var sha224: String? {
		return String(digestData: hashData?.sha224, length: CC_SHA224_DIGEST_LENGTH)
	}

	public var sha256: String? {
		return String(digestData: hashData?.sha256, length: CC_SHA256_DIGEST_LENGTH)
	}

	public var sha384: String? {
		return String(digestData: hashData?.sha384, length: CC_SHA384_DIGEST_LENGTH)
	}

	public var sha512: String? {
		return String(digestData: hashData?.sha512, length: CC_SHA512_DIGEST_LENGTH)
	}


	// MARK: - HMAC

	public func hmac(key: String, algorithm: HMAC.Algorithm) -> String? {
		return HMAC.sign(message: self, algorithm: algorithm, key: key)
	}


	// MARK: - Private

	private var hashData: Data? {
		return data(using: String.Encoding.utf8)
	}

	private init?(digestData: Data?, length: Int32) {
		guard let digestData = digestData else { return nil }
		var digest = [UInt8](repeating: 0, count: Int(length))
		(digestData as NSData).getBytes(&digest, length: Int(length) * sizeof(UInt8))

		var string = ""
		for i in 0..<length {
			string += String(format: "%02x", digest[Int(i)])
		}
		self.init(string)
	}
}
