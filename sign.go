package main

import (
	"bytes"
	"io"
	"os"

	"github.com/miekg/pkcs11"
)

func signAction() error {
	var err error

	// File descriptor for the input file
	var fd io.ReadCloser

	// Choose either the first non-flag argument or stdin
	if len(flags.OtherArgs) == 1 {
		fd, err = os.Open(flags.OtherArgs[0])
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

	// Create and initialize the PKCS#11 context
	p := pkcs11.New(config.PKCS11Path)
	err = p.Initialize()
	if err != nil {
		return err
	}

	defer p.Destroy()
	defer p.Finalize()

	slots, err := p.GetSlotList(true)
	if err != nil {
		return err
	}

	session, err := p.OpenSession(slots[0], pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	if err != nil {
		return err
	}
	defer p.CloseSession(session)

	err = p.Login(session, pkcs11.CKU_USER, config.PIN)
	if err != nil {
		return err
	}
	defer p.Logout(session)

	// Find the private key
	temp := []*pkcs11.Attribute{pkcs11.NewAttribute(pkcs11.CKA_SIGN, true)}
	err = p.FindObjectsInit(session, temp)
	if err != nil {
		return err
	}

	objs, _, err := p.FindObjects(session, 100)
	if err != nil {
		return err
	}
	p.FindObjectsFinal(session)

	// Find the public key
	temp2 := []*pkcs11.Attribute{pkcs11.NewAttribute(pkcs11.CKA_VERIFY, true)}
	err = p.FindObjectsInit(session, temp2)
	if err != nil {
		return err
	}

	objs2, _, err := p.FindObjects(session, 100)
	if err != nil {
		return err
	}
	p.FindObjectsFinal(session)

	// Sign the data in the input buffer
	err = p.SignInit(session, []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS, nil)}, objs[0])
	if err != nil {
		return err
	}

	inputData := inputBuffer.Bytes()
	sig, err := p.Sign(session, inputData)
	if err != nil {
		return err
	}

	// Verify the signature we just created
	err = p.VerifyInit(session, []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS, nil)}, objs2[0])
	if err != nil {
		return err
	}

	err = p.Verify(session, inputData, sig)
	if err != nil {
		return err
	}

	return nil
}
