package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"os/user"
	"path/filepath"

	"github.com/bitcynth/cynpkcs11"
	"github.com/pborman/getopt"
)

// specified with: go build -ldflags "-X main.versionString=$VERSION_STR"
var versionString = "undefined"

var (
	helpFlag     = getopt.BoolLong("help", 'h', "")
	versionFlag  = getopt.BoolLong("version", 'v', "")
	signFlag     = getopt.BoolLong("sign", 's', "")
	verifyFlag   = getopt.BoolLong("verify", 0, "")
	listKeysFlag = getopt.BoolLong("list-keys", 0, "")

	localUserOption = getopt.StringLong("local-user", 'u', "", "USER-ID")
	detachSignFlag  = getopt.BoolLong("detach-sign", 'b', "")
	armorFlag       = getopt.BoolLong("armor", 'a', "")
	statusFdOption  = getopt.IntLong("status-fd", 0, -1, "")
	keyFormatOption = getopt.EnumLong("keyid-format", 0, []string{"long"}, "")

	otherArgs []string
)

// Config represents the config file
type Config struct {
	PIN                  string `json:"pin"`
	PKCS11Path           string `json:"pkcs11_path"`
	TimestampURL         string `json:"timestamp_url"`
	CertificateChainPath string `json:"certificate_chain"`
}

var config Config

// Just parses the config file
func parseConfig() {
	usr, err := user.Current()
	if err != nil {
		panic(err)
	}

	configFile := filepath.Join(usr.HomeDir, ".config/pkcs11smimesign.json")
	configBytes, err := ioutil.ReadFile(configFile)
	if err != nil {
		panic(err)
	}

	err = json.Unmarshal(configBytes, &config)
	if err != nil {
		panic(err)
	}
}

func main() {
	getopt.Parse()
	otherArgs = getopt.Args()

	parseConfig()

	if *versionFlag {
		fmt.Printf("pkcs11smimesign - v%s\n", versionString)
		fmt.Println("Copyright (C) 2020 Cynthia Revström")
		return
	}

	if *listKeysFlag {
		ctx, err := cynpkcs11.New(cynpkcs11.ContextOptions{
			PIN:          config.PIN,
			PKCS11Module: config.PKCS11Path,
		})
		if err != nil {
			panic(err)
		}
		defer ctx.Close()
		certs, err := ctx.GetCertificates()
		if err != nil {
			panic(err)
		}
		log.Println(certs[0].Subject.Names)
		return
	}

	if *signFlag {
		err := signAction()
		if err != nil {
			panic(err)
		}
		return
	}

	if *verifyFlag {
		err := verifyAction()
		if err != nil {
			panic(err)
		}
		return
	}
}
