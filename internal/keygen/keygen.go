package keygen

import (
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path"

	"github.com/icyflame/wireguard-configuration-generator/internal/configuration"
)

const (
	PrivateKey = "private"
	PublicKey  = "public"
)

// GenerateKeys ...
func GenerateKeys(networkName string, config configuration.NetworkConfig, baseDir string) error {
	for _, client := range append(config.Clients, config.Server) {
		err := writeKey(baseDir, networkName, client)
		if err != nil {
			return fmt.Errorf("could not write keys to filesystem: %w", err)
		}
	}

	return nil
}

// writeKey ...
func writeKey(baseDir, networkName string, peer configuration.Peer) error {
	directory := path.Join(baseDir, networkName, peer.Identifier)
	keyLocation := path.Join(directory, PrivateKey)
	if _, err := os.Stat(keyLocation); err == nil {
		return nil
	}

	err := os.MkdirAll(directory, 0700)
	if err != nil {
		return fmt.Errorf("could not make directory: %w", err)
	}

	privateKey, err := generatePrivateKey(keyLocation)
	if err != nil {
		return fmt.Errorf("could not generate private key for %s > %s > %s: %w", baseDir, networkName, peer.Identifier, err)
	}

	publicKeyLocation := path.Join(directory, PublicKey)
	err = generatePublicKey(privateKey, publicKeyLocation)
	if err != nil {
		return fmt.Errorf("could not generate public key for %s > %s > %s: %w", baseDir, networkName, peer.Identifier, err)
	}

	return nil

}

// generatePrivateKey ...
func generatePrivateKey(location string) ([]byte, error) {
	cmd := exec.Command("wg", "genkey")
	privateKey, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("could not generate private key: %w", err)
	}

	err = os.WriteFile(location, privateKey, 0600)
	if err != nil {
		return nil, fmt.Errorf("could not write private key to file: %w", err)
	}

	log.Print("written to " + location)

	return privateKey, nil
}

// generatePublicKey ...
func generatePublicKey(privateKey []byte, location string) error {
	cmd := exec.Command("wg", "pubkey")
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return fmt.Errorf("could not get stdin of pubkey command: %w", err)
	}

	go func() {
		defer stdin.Close()
		io.WriteString(stdin, string(privateKey))
	}()

	publicKey, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("could not generate public key: %w", err)
	}

	err = os.WriteFile(location, publicKey, 0600)
	if err != nil {
		return fmt.Errorf("could not write private key to file: %w", err)
	}

	return nil
}
