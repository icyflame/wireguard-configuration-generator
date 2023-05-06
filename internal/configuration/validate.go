package configuration

import (
	"fmt"

	"github.com/icyflame/wireguard-configuration-generator/internal/utils"
)

type ConfigurationValidator struct{}

// Validate ...
func (c *ConfigurationValidator) Validate(config NetworkConfig) error {
	var addresses []string
	for _, client := range append(config.Clients, config.Server) {
		addresses = append(addresses, client.Address)
	}

	if !utils.IsUnique(addresses) {
		return fmt.Errorf("addresses must be unique")
	}

	var identifiers []string
	for _, client := range append(config.Clients, config.Server) {
		identifiers = append(identifiers, client.Identifier)
	}

	if !utils.IsUnique(identifiers) {
		return fmt.Errorf("identifiers must be unique")
	}

	return nil
}
