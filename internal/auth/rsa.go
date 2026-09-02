package auth

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
)

// verifyRSA checks a PKCS#1 v1.5 signature over the signing input.
func verifyRSA(alg string, key *rsa.PublicKey, signed, sig []byte) error {
	var (
		hash crypto.Hash
		sum  []byte
	)
	switch alg {
	case "RS256":
		h := sha256.Sum256(signed)
		hash, sum = crypto.SHA256, h[:]
	case "RS512":
		h := sha512.Sum512(signed)
		hash, sum = crypto.SHA512, h[:]
	default:
		return fmt.Errorf("unsupported algorithm %q", alg)
	}
	return rsa.VerifyPKCS1v15(key, hash, sum, sig)
}
