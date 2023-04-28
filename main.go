package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/icyflame/wireguard-configuration-generator/internal/configuration"
)

const (
	ExitOK = iota
	ExitErr
)

func main() {
	err, returnCode := _main()
	if err != nil {
		log.Fatalf("exit with error", err)
	}
	os.Exit(returnCode)
}

func _main() (error, int) {
	var configurationFile string
	flag.StringVar(&configurationFile, "configuration-file", "", "configuration file for generating wireguard configurations")
	flag.Parse()

	if configurationFile == "" {
		flag.PrintDefaults()
		return fmt.Errorf("insufficient arguments"), ExitErr
	}

	log.Print(configurationFile)
	networkConfig, err := configuration.Read(configurationFile)
	if err != nil {
		return fmt.Errorf("could not read config file: %w", err), ExitErr
	}

	fmt.Printf("%#v", networkConfig)

	return nil, ExitOK
}
