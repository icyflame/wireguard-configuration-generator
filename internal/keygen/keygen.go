package keygen

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"path"
	"strings"

	"github.com/icyflame/wireguard-configuration-generator/internal/configuration"
)

const (
	PrivateKey = "private"
	PublicKey  = "public"
)

type KeyGenerator struct {
	Base string
}

// GenerateKeys ...
func (k *KeyGenerator) GenerateKeys(networkName string, config configuration.NetworkConfig) error {
	for _, client := range append(config.Clients, config.Server) {
		err := writeKey(k.Base, networkName, client)
		if err != nil {
			return fmt.Errorf("could not write keys to filesystem: %w", err)
		}
	}

	return nil
}

type KeyRetriever struct {
	Base string
}

// GetPrivateKey ...
func (kr *KeyRetriever) GetPrivateKey(networkName, identifier string) (string, error) {
	directory := getKeyLocation(kr.Base, networkName, identifier)
	keyLocation := path.Join(directory, PrivateKey)
	if _, err := os.Stat(keyLocation); err != nil {
		return "", fmt.Errorf("private key file does not exist: %w", err)
	}

	key, err := os.ReadFile(keyLocation)
	if err != nil {
		return "", fmt.Errorf("could not read the file at %s: %w", keyLocation, err)
	}

	return strings.Trim(string(key), "\n"), nil
}

// GetPublicKey ...
func (kr *KeyRetriever) GetPublicKey(networkName, identifier string) (string, error) {
	directory := getKeyLocation(kr.Base, networkName, identifier)
	keyLocation := path.Join(directory, PublicKey)
	if _, err := os.Stat(keyLocation); err != nil {
		return "", fmt.Errorf("public key file does not exist: %w", err)
	}

	key, err := os.ReadFile(keyLocation)
	if err != nil {
		return "", fmt.Errorf("could not read the file at %s: %w", keyLocation, err)
	}

	return strings.Trim(string(key), "\n"), nil
}

// getKeyLocation ...
func getKeyLocation(baseDir, networkName, identifier string) string {
	return path.Join(baseDir, networkName, identifier)
}

// writeKey ...
func writeKey(baseDir, networkName string, peer configuration.Peer) error {
	kr := KeyRetriever{
		Base: baseDir,
	}

	if _, err := kr.GetPrivateKey(networkName, peer.Identifier); err == nil {
		return nil
	}

	directory := getKeyLocation(baseDir, networkName, peer.Identifier)
	err := os.MkdirAll(directory, 0700)
	if err != nil {
		return fmt.Errorf("could not make directory: %w", err)
	}

	keyLocation := path.Join(directory, PrivateKey)
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
