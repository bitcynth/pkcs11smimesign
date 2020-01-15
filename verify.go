package main

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"os"

	"github.com/mastahyeti/cms"
)

func verifyAction() error {
	sNewSig.emit()

	if len(otherArgs) < 2 {
		return verifyAttached()
	}

	return verifyDetached()
}

func verifyAttached() error {
	return nil
}

func verifyDetached() error {
	var fd io.ReadCloser
	var err error

	fd, err = os.Open(otherArgs[0])
	if err != nil {
		return err
	}
	defer fd.Close()

	buffer := new(bytes.Buffer)
	_, err = io.Copy(buffer, fd)
	if err != nil {
		return err
	}

	var der []byte
	block, _ := pem.Decode(buffer.Bytes())
	if block != nil {
		der = block.Bytes
	} else {
		der = buffer.Bytes()
	}

	sd, err := cms.ParseSignedData(der)
	if err != nil {
		return err
	}

	if otherArgs[1] == "-" {
		fd = os.Stdin
	} else {
		fd, err = os.Open(otherArgs[1])
		if err != nil {
			return err
		}
		defer fd.Close()
	}

	buffer.Reset()
	_, err = io.Copy(buffer, fd)
	if err != nil {
		return err
	}

	chains, err := sd.VerifyDetached(buffer.Bytes(), verifyOptions())
	if err != nil {
		if len(chains) > 0 {
			emitBadSig(chains)
		} else {
			sErrSig.emit()
		}

		return err
	}

	cert := chains[0][0][0]
	fp := certHexFP(cert)
	subject := cert.Subject.String()

	fmt.Fprintf(os.Stderr, "pkcs11smimesign: Signature made using certificate ID 0x%s\n", fp)
	emitGoodSig(chains)

	fmt.Fprintf(os.Stderr, "pkcs11smimesign: Good singature from \"%s\"\n", subject)
	emitTrustFully()

	return nil
}

func verifyOptions() x509.VerifyOptions {
	roots, err := x509.SystemCertPool()
	if err != nil {
		roots = x509.NewCertPool()
	}

	chain, _ := loadChain()
	for _, cert := range chain {
		roots.AddCert(cert)
	}

	return x509.VerifyOptions{
		Roots:     roots,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}
}
