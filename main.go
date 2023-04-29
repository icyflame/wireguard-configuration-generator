package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/icyflame/wireguard-configuration-generator/internal/configuration"
	"github.com/icyflame/wireguard-configuration-generator/internal/keygen"
)

const (
	ExitOK = iota
	ExitErr
)

func main() {
	err, returnCode := _main()
	if err != nil {
		log.Fatal("exit with error: ", err)
	}
	os.Exit(returnCode)
}

func _main() (error, int) {
	var configurationFile string
	var keysBaseDirectory string
	flag.StringVar(&configurationFile, "configuration-file", "", "configuration file for generating wireguard configurations")
	flag.StringVar(&keysBaseDirectory, "keys-base-dir", "", "base directory for storing the private and public keys required for wireguard")
	flag.Parse()

	if configurationFile == "" || keysBaseDirectory == "" {
		flag.PrintDefaults()
		return fmt.Errorf("insufficient arguments"), ExitErr
	}

	log.Print(configurationFile)
	networkConfig, err := configuration.Read(configurationFile)
	if err != nil {
		return fmt.Errorf("could not read config file: %w", err), ExitErr
	}

	fmt.Printf("%#v\n", networkConfig)

	for networkName, config := range networkConfig {
		err := configuration.Validate(config)
		if err != nil {
			return fmt.Errorf("configuration for network %s is invalid: %w", networkName, err), ExitErr
		}

		err = keygen.GenerateKeys(networkName, config, keysBaseDirectory)
		if err != nil {
			return fmt.Errorf("could not generate all keys for %s: %w", networkName, err), ExitErr
		}
	}

	fmt.Printf("configuration is valid")

	return nil, ExitOK
}
