package configuration

import (
	"fmt"

	"github.com/icyflame/wireguard-configuration-generator/internal/utils"
)

type ConfigurationValidator struct{}

// Validate ...
func (c *ConfigurationValidator) Validate(config NetworkConfig) error {
	switch config.Type {
	case NetworkConfigType_ServerClient:
	case NetworkConfigType_FullMesh:
		// pass
	default:
		return fmt.Errorf("network configuration type must be non-empty and valid for network")
	}

	if config.Type == NetworkConfigType_ServerClient && (config.Server.Address == "" || config.Server.Endpoint == "" || config.Server.Identifier == "") {
		return fmt.Errorf("server-client configuration type must have a server defined with identifier, address, and endpoint")
	}

	// Full mesh configuration has no server. Only clients which are all connected to each other.
	if config.Type == NetworkConfigType_FullMesh {
		config.Server = Peer{}
	}

	allClients := config.Clients
	if config.Type == NetworkConfigType_ServerClient {
		allClients = append(config.Clients, config.Server)
	}

	var addresses []string
	for _, client := range allClients {
		addresses = append(addresses, client.Address)
	}

	if !utils.IsUnique(addresses) {
		return fmt.Errorf("addresses must be unique")
	}

	var identifiers []string
	for _, client := range allClients {
		identifiers = append(identifiers, client.Identifier)
	}

	if !utils.IsUnique(identifiers) {
		return fmt.Errorf("identifiers must be unique")
	}

	return nil
}
