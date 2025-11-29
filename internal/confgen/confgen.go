package confgen

import (
	"fmt"
	"os"
	"path"
	"text/template"

	"github.com/icyflame/wireguard-configuration-generator/internal/configuration"
	"github.com/icyflame/wireguard-configuration-generator/internal/keygen"
)

type WireguardConfigurationGenerator struct {
	PeerConfigFile string
	KR             *keygen.KeyRetriever
	Base           string
	DNSServer      string
}

type NetworkConfig struct {
	NetworkName        string
	Mask               string
	Identifier         string
	Address            string
	PrivateKey         string
	PostUpDownRequired bool
	DNSServer          string
	Peers              []PeerConfig
}

type PeerConfig struct {
	PublicKey  string
	AllowedIPs string
	Identifier string
	Endpoint   string
}

// Generate ...
func (w *WireguardConfigurationGenerator) Generate(networkName string, config configuration.NetworkConfig) error {
	if config.Type == configuration.NetworkConfigType_ServerClient {
		if err := w.generatePeerConfiguration(networkName, config.Server, config.Clients, false); err != nil {
			return fmt.Errorf("could not generate server configuration in %s: %w", networkName, err)
		}
	}

	for i, client := range config.Clients {
		var allOtherClients []configuration.Peer
		switch config.Type {
		case configuration.NetworkConfigType_FullMesh:
			for j, client := range config.Clients {
				if i == j {
					continue
				}
				allOtherClients = append(allOtherClients, client)
			}
		case configuration.NetworkConfigType_ServerClient:
			allOtherClients = []configuration.Peer{
				config.Server,
			}
		}

		// When configuration is server client, client should allow server (which is its only peer) to represent any IP address
		// But when configuration is full mesh, client should allow other clients to represent only their own IP address
		if err := w.generatePeerConfiguration(networkName, client, allOtherClients, config.Type == configuration.NetworkConfigType_ServerClient); err != nil {
			return fmt.Errorf("could not generate client configuration for %s > %s: %w", networkName, client.Identifier, err)
		}
	}

	return nil
}

// generatePeerConfiguration ...
func (w *WireguardConfigurationGenerator) generatePeerConfiguration(networkName string, server configuration.Peer, peers []configuration.Peer, allowAllIPs bool) error {
	if allowAllIPs && len(peers) > 1 {
		return fmt.Errorf("can not allow all IPs through multiple peers - that setup does not make sense. (%s > %s)", networkName, server.Identifier)
	}

	configFile, err := os.ReadFile(w.PeerConfigFile)
	if err != nil {
		return fmt.Errorf("could not template peer configuration: %w", err)
	}

	t := template.Must(template.New("peer").Parse(string(configFile)))

	privKey, err := w.KR.GetPrivateKey(networkName, server.Identifier)
	if err != nil {
		return fmt.Errorf("could not get private key for %s > %s: %w", networkName, server.Identifier, err)
	}

	c := NetworkConfig{
		NetworkName: networkName,
		Identifier:  server.Identifier,
		Mask:        "32",
		Address:     server.Address,
		PrivateKey:  privKey,
		DNSServer:   w.DNSServer,

		// If all IPs are being allowed, then this is a client which will tunnel all its traffic
		// through a server. That client does not need the "PostUp/Down" setup for IP tables.
		//
		// TODO: Do we need this block anymore? What exactly does it do? I have started noticing
		// that configuration QR codes which embed this line are not accepted by the iOS or Android
		// application anymore.
		PostUpDownRequired: !allowAllIPs,
	}

	for _, peer := range peers {
		pubKey, err := w.KR.GetPublicKey(networkName, peer.Identifier)
		if err != nil {
			return fmt.Errorf("could not get public key for %s > %s: %w", networkName, peer.Identifier, err)
		}
		thisPeer := PeerConfig{
			PublicKey:  pubKey,
			Endpoint:   peer.Endpoint,
			Identifier: peer.Identifier,
		}

		thisPeer.AllowedIPs = peer.Address + "/32"
		if allowAllIPs {
			thisPeer.AllowedIPs = "0.0.0.0/0, ::/0"
		}

		c.Peers = append(c.Peers, thisPeer)
	}

	outputFileLocation := path.Join(w.Base, networkName)
	if err := os.MkdirAll(outputFileLocation, 0700); err != nil {
		return fmt.Errorf("could not create output directory for configurations %s: %w", outputFileLocation, err)
	}

	outputFileName := path.Join(outputFileLocation, server.Identifier+".conf")

	f, err := os.Create(outputFileName)
	if err != nil {
		return fmt.Errorf("could not create server conf file: %w", err)
	}
	defer f.Close()

	if err := f.Chmod(0600); err != nil {
		return fmt.Errorf("could not protect file by setting permission bits to 600 %s: %w", outputFileName, err)
	}

	if err := t.Execute(f, c); err != nil {
		return fmt.Errorf("could not execute template on the variable: %w", err)
	}

	return nil
}
