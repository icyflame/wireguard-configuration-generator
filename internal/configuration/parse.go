package configuration

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
)

type Peer struct {
	Identifier string `json:"identifier"`
	Address    string `json:"address"`
	Endpoint   string `json:"endpoint"`
}

type NetworkConfigType string

const (
	NetworkConfigType_Unknown      = "unknown"
	NetworkConfigType_ServerClient = "server-client"
)

type NetworkConfig struct {
	Type    NetworkConfigType `json:"type"`
	Server  Peer              `json:"server"`
	Clients []Peer            `json:"clients"`
}

// Read ...
func Read(fileName string) (map[string]NetworkConfig, error) {
	jsonFH, err := os.Open(fileName)
	if err != nil {
		return nil, fmt.Errorf("could not open file descriptor: %v", err)
	}
	jsonBytes, err := io.ReadAll(jsonFH)
	if err != nil {
		return nil, fmt.Errorf("could not read from file: %v", err)
	}

	output := make(map[string]NetworkConfig)
	err = json.Unmarshal(jsonBytes, &output)
	if err != nil {
		return nil, fmt.Errorf("could not parse file as JSON: %v", err)
	}

	return output, err
}
