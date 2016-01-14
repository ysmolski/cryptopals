package util

import (
	"crypto/sha1"
	"crypto/sha256"
)

func HMacSha1(key, msg []byte) []byte {
	if len(key) > sha1.BlockSize {
		hash := sha1.Sum(key)
		key = make([]byte, len(hash))
		copy(key, hash[:20])
	}
	if len(key) < sha1.BlockSize {
		key = append(key, make([]byte, sha1.BlockSize-len(key))...)
	}
	ipad := make([]byte, len(key))
	opad := make([]byte, len(key))
	for i := 0; i < len(key); i++ {
		ipad[i] = key[i] ^ 0x36
		opad[i] = key[i] ^ 0x5c
	}
	internal := sha1.Sum(append(ipad, msg...))
	hash := sha1.Sum(append(opad, internal[:20]...))
	return hash[:20]
}

func HMacSha256(key, msg []byte) []byte {
	if len(key) > sha256.BlockSize {
		hash := sha256.Sum256(key)
		key = make([]byte, len(hash))
		copy(key, hash[:32])
	}
	if len(key) < sha256.BlockSize {
		key = append(key, make([]byte, sha256.BlockSize-len(key))...)
	}
	ipad := make([]byte, len(key))
	opad := make([]byte, len(key))
	for i := 0; i < len(key); i++ {
		ipad[i] = key[i] ^ 0x36
		opad[i] = key[i] ^ 0x5c
	}
	internal := sha256.Sum256(append(ipad, msg...))
	hash := sha256.Sum256(append(opad, internal[:32]...))
	return hash[:32]
}
