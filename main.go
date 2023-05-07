package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/icyflame/wireguard-configuration-generator/internal/confgen"
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
	var confsBaseDirectory string
	flag.StringVar(&configurationFile, "configuration-file", "", "configuration file for generating wireguard configurations")
	flag.StringVar(&keysBaseDirectory, "keys-base-dir", "", "base directory for storing the private and public keys required for wireguard")
	flag.StringVar(&confsBaseDirectory, "confs-base-dir", "", "base directory for storing the wireguard configurations")
	flag.Parse()

	if configurationFile == "" || keysBaseDirectory == "" || confsBaseDirectory == "" {
		flag.PrintDefaults()
		return fmt.Errorf("insufficient arguments"), ExitErr
	}

	networkConfig, err := configuration.Read(configurationFile)
	if err != nil {
		return fmt.Errorf("could not read config file: %w", err), ExitErr
	}

	configValidator := &configuration.ConfigurationValidator{}
	keyGenerator := &keygen.KeyGenerator{
		Base: keysBaseDirectory,
	}
	wgConfigGenerator := &confgen.WireguardConfigurationGenerator{
		PeerConfigFile: "./template-configurations/peer.conf",
		KR: &keygen.KeyRetriever{
			Base: keysBaseDirectory,
		},
		Base: confsBaseDirectory,
	}

	for networkName, config := range networkConfig {
		err := configValidator.Validate(config)
		if err != nil {
			return fmt.Errorf("configuration for network %s is invalid: %w", networkName, err), ExitErr
		}

		err = keyGenerator.GenerateKeys(networkName, config)
		if err != nil {
			return fmt.Errorf("could not generate all keys for %s: %w", networkName, err), ExitErr
		}

		err = wgConfigGenerator.Generate(networkName, config)
		if err != nil {
			return fmt.Errorf("could not generate all the configuration files for %s: %w", networkName, err), ExitErr
		}
	}

	return nil, ExitOK
}
