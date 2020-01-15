package main

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"io"
	"io/ioutil"
	"os"

	"github.com/bitcynth/cynpkcs11"
	"github.com/mastahyeti/cms"
)

func signAction() error {
	var err error

	// File descriptor for the input file
	var fd io.ReadCloser

	// Choose either the first non-flag argument or stdin
	if len(otherArgs) == 1 {
		fd, err = os.Open(otherArgs[0])
		if err != nil {
			return err
		}
	} else {
		fd = os.Stdin
	}

	// Read the data from the input fd to the input buffer
	inputBuffer := new(bytes.Buffer)
	_, err = io.Copy(inputBuffer, fd)
	if err != nil {
		return err
	}

	sBeginSigning.emit()

	// Create and initialize the PKCS#11 context
	ctx, err := cynpkcs11.New(cynpkcs11.ContextOptions{
		PIN:          config.PIN,
		PKCS11Module: config.PKCS11Path,
	})
	if err != nil {
		return err
	}
	defer ctx.Close()

	sd, err := cms.NewSignedData(inputBuffer.Bytes())
	if err != nil {
		return err
	}

	certs, err := ctx.GetCertificates()
	if err != nil {
		return err
	}

	err = ctx.Signer.Initialize()
	if err != nil {
		return err
	}

	err = sd.Sign([]*x509.Certificate{certs[0]}, ctx.Signer)
	if err != nil {
		return err
	}

	if *detachSignFlag {
		sd.Detached()
	}

	if len(config.TimestampURL) > 0 {
		err = sd.AddTimestamps(config.TimestampURL)
		if err != nil {
			return err
		}
	}

	chain, err := loadChain()
	if err != nil {
		return err
	}
	chain = removeRootFromChain(chain)

	err = sd.SetCertificates(chain)
	if err != nil {
		return err
	}

	der, err := sd.ToDER()
	if err != nil {
		return err
	}

	emitSigCreated(certs[0], *detachSignFlag)

	if *armorFlag {
		err = pem.Encode(os.Stdout, &pem.Block{
			Type:  "SIGNED MESSAGE",
			Bytes: der,
		})
	} else {
		_, err = os.Stdout.Write(der)
	}
	if err != nil {
		return err
	}

	return nil
}

func loadChain() ([]*x509.Certificate, error) {
	chainFileBytes, err := ioutil.ReadFile(config.CertificateChainPath)
	if err != nil {
		return nil, err
	}

	var certs []*x509.Certificate

	block, rest := pem.Decode(chainFileBytes)
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}
	certs = append(certs, cert)
	for len(rest) != 0 {
		block, rest = pem.Decode(rest)
		cert, err = x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		certs = append(certs, cert)
	}

	return certs, nil
}

func removeRootFromChain(chain []*x509.Certificate) []*x509.Certificate {
	for i, cert := range chain {
		if bytes.Equal(cert.RawIssuer, cert.RawSubject) {
			copy(chain[i:], chain[i+1:])
			chain[len(chain)-1] = nil
			chain = chain[:len(chain)-1]
			break
		}
	}

	return chain
}
