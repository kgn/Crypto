//
//  NSData+Crypto.swift
//  Crypto
//
//  Created by Sam Soffes on 4/21/15.
//  Copyright (c) 2015 Sam Soffes. All rights reserved.
//

import Foundation
import CommonCrypto

extension Data {

	// MARK: - Digest

	public var md2: Data {
		let hash = Digest.md2(bytes: bytes, length: UInt32(count))
		return Data(bytes: UnsafePointer<UInt8>(hash), count:  hash.count)
	}

	public var md4: Data {
		let hash = Digest.md4(bytes: bytes, length: UInt32(count))
		return Data(bytes: UnsafePointer<UInt8>(hash), count:  hash.count)
	}

	public var md5: Data {
		let hash = Digest.md5(bytes: bytes, length: UInt32(count))
		return Data(bytes: UnsafePointer<UInt8>(hash), count:  hash.count)
	}

	public var sha1: Data {
		let hash = Digest.sha1(bytes: bytes, length: UInt32(count))
		return Data(bytes: UnsafePointer<UInt8>(hash), count:  hash.count)
	}

	public var sha224: Data {
		let hash = Digest.sha224(bytes: bytes, length: UInt32(count))
		return Data(bytes: UnsafePointer<UInt8>(hash), count:  hash.count)
	}

	public var sha256: Data {
		let hash = Digest.sha256(bytes: bytes, length: UInt32(count))
		return Data(bytes: UnsafePointer<UInt8>(hash), count:  hash.count)
	}

	public var sha384: Data {
		let hash = Digest.sha384(bytes: bytes, length: UInt32(count))
		return Data(bytes: UnsafePointer<UInt8>(hash), count:  hash.count)
	}

	public var sha512: Data {
		let hash = Digest.sha512(bytes: bytes, length: UInt32(count))
		return Data(bytes: UnsafePointer<UInt8>(hash), count:  hash.count)
	}


	// MARK: - HMAC

	public func hmac(key: Data, algorithm: HMAC.Algorithm) -> Data {
		return HMAC.sign(data: self, algorithm: algorithm, key: key) as Data
	}


	// MARK: - Internal

	var bytes: UnsafePointer<UInt8> {
		let buffer = UnsafeMutablePointer<UInt8>(allocatingCapacity: count)
		copyBytes(to: buffer, count: count)
		return UnsafePointer<UInt8>(buffer)
	}
}
