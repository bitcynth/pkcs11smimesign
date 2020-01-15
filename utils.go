package main

import (
	"crypto/sha1"
	"crypto/x509"
	"encoding/hex"
)

func certHexFP(cert *x509.Certificate) string {
	fp := sha1.Sum(cert.Raw)
	return hex.EncodeToString(fp[:])
}
