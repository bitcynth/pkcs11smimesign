package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"os/user"
	"path/filepath"
)

// specified with: go build -ldflags "-X main.versionString=$VERSION_STR"
var versionString = "undefined"

// Flags represent the flags that can be passed to the application
type Flags struct {
	OtherArgs    []string
	HelpFlag     bool
	VersionFlag  bool
	SignFlag     bool
	VerifyFlag   bool
	ListKeysFlag bool
	ArmorFlag    bool
	DetachSign   bool
}

// Config represents the config file
type Config struct {
	PIN        string `json:"pin"`
	PKCS11Path string `json:"pkcs11_path"`
}

var flags Flags
var config Config

// This is a terrible system, I know, it will be fixed soon(tm)
func parseArgs() {
	flags = Flags{}
	for _, arg := range os.Args[1:] {
		if arg == "--help" {
			flags.HelpFlag = true
		} else if arg == "--version" {
			flags.VersionFlag = true
		} else if arg == "--sign" || arg == "-s" {
			flags.SignFlag = true
		} else if arg == "--armor" || arg == "-a" {
			flags.ArmorFlag = true
		} else if arg == "--detach-sign" || arg == "-d" {
			flags.DetachSign = true
		} else {
			flags.OtherArgs = append(flags.OtherArgs, arg)
		}
	}
}

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
	parseArgs()
	parseConfig()

	if flags.VersionFlag {
		fmt.Printf("pkcs11smimesign - v%s\n", versionString)
		fmt.Println("Copyright (C) 2020 Cynthia Revström")
		return
	}

	if flags.SignFlag {
		err := signAction()
		if err != nil {
			panic(err)
		}
		return
	}
}
