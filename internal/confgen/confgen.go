package confgen

import (
	"fmt"
	"os"
	"text/template"

	"github.com/icyflame/wireguard-configuration-generator/internal/configuration"
	"github.com/icyflame/wireguard-configuration-generator/internal/keygen"
)

type WireguardConfigurationGenerator struct {
	PeerConfigFile string
	KR             *keygen.KeyRetriever
}

type NetworkConfig struct {
	NetworkName string
	Mask        string
	Identifier  string
	Address     string
	PrivateKey  string
	Peers       []PeerConfig
}

type PeerConfig struct {
	PublicKey  string
	AllowedIPs string
	Identifier string
	Endpoint   string
}

// Generate ...
func (w *WireguardConfigurationGenerator) Generate(networkName string, config configuration.NetworkConfig) error {
	err := w.generateServerConfiguration(networkName, config)
	if err != nil {
		return fmt.Errorf("could not generate server configuration in %s: %w", networkName, err)
	}

	for _, client := range config.Clients {
		err := w.generateClientConfiguration(networkName, client, config.Server)
		if err != nil {
			return fmt.Errorf("could not generate client configuration for %s > %s: %w", networkName, client.Identifier, err)
		}
	}

	return nil
}

// generateServerConfiguration ...
func (w *WireguardConfigurationGenerator) generateServerConfiguration(networkName string, config configuration.NetworkConfig) error {
	configFile, err := os.ReadFile(w.PeerConfigFile)
	if err != nil {
		return fmt.Errorf("could not template peer configuration: %w", err)
	}

	t := template.Must(template.New("peer").Parse(string(configFile)))
	privKey, err := w.KR.GetPrivateKey(networkName, config.Server.Identifier)
	if err != nil {
		return fmt.Errorf("could not get private key for %s > %s: %w", networkName, config.Server.Identifier, err)
	}
	c := NetworkConfig{
		NetworkName: networkName,
		Identifier:  config.Server.Identifier,
		Mask:        "24",
		Address:     config.Server.Address,
		PrivateKey:  privKey,
	}

	for _, client := range config.Clients {
		pubKey, err := w.KR.GetPublicKey(networkName, client.Identifier)
		if err != nil {
			return fmt.Errorf("could not get public key for %s > %s: %w", networkName, client.Identifier, err)
		}
		c.Peers = append(c.Peers, PeerConfig{
			PublicKey:  pubKey,
			AllowedIPs: client.Address + "/32",
			Endpoint:   client.Endpoint,
			Identifier: client.Identifier,
		})
	}

	f, _ := os.Open("server.conf")
	defer f.Close()
	err = t.Execute(f, c)
	if err != nil {
		return fmt.Errorf("could not execute template on the variable: %w", err)
	}

	return nil
}

// generateServerConfiguration ...
func (w *WireguardConfigurationGenerator) generateClientConfiguration(networkName string, client, server configuration.Peer) error {
	configFile, err := os.ReadFile(w.PeerConfigFile)
	if err != nil {
		return fmt.Errorf("could not template peer configuration: %w", err)
	}

	t := template.Must(template.New("peer").Parse(string(configFile)))
	privKey, err := w.KR.GetPrivateKey(networkName, client.Identifier)
	if err != nil {
		return fmt.Errorf("could not get private key for %s > %s: %w", networkName, client.Identifier, err)
	}
	c := NetworkConfig{
		NetworkName: networkName,
		Identifier:  client.Identifier,
		Mask:        "32",
		Address:     client.Address,
		PrivateKey:  privKey,
	}

	for _, peer := range []configuration.Peer{
		server,
	} {
		pubKey, err := w.KR.GetPublicKey(networkName, peer.Identifier)
		if err != nil {
			return fmt.Errorf("could not get public key for %s > %s: %w", networkName, peer.Identifier, err)
		}
		c.Peers = append(c.Peers, PeerConfig{
			PublicKey:  pubKey,
			AllowedIPs: "0.0.0.0/0",
			Endpoint:   peer.Endpoint,
			Identifier: peer.Identifier,
		})
	}

	f, _ := os.Open("client.conf")
	defer f.Close()
	err = t.Execute(f, c)
	if err != nil {
		return fmt.Errorf("could not execute template on the variable: %w", err)
	}

	return nil
}
