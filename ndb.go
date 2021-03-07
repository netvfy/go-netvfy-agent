package agent

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
)

// NetworkCredentials is the network informations.
type NetworkCredentials struct {
	Name   string `json:"name"`
	APIsrv string `json:"api_srv"`
	PVkey  string `json:"pvkey"`
	Cert   string `json:"cert"`
	CAcert string `json:"cacert"`
}

// Ndb is the network database.
type Ndb struct {
	Version  int                  `json:"version"`
	Networks []NetworkCredentials `json:"networks"`
}

// GetNdbPath returns the path of the network database.
func GetNdbPath() string {
	// FIXME make it works on Windows too
	return os.Getenv("HOME") + "/.config/netvfy/nvagent.json"
}

// FetchNetworks returns a populated network database object.
func FetchNetworks(ndbPath string) (*Ndb, error) {

	var ndb Ndb

	// Read the network database
	byteValue, err := ioutil.ReadFile(ndbPath)
	if err != nil {
		return nil, fmt.Errorf("FetchNetworks: failed to read the network database: %v", err)
	}

	err = json.Unmarshal(byteValue, &ndb)
	if err != nil {
		return nil, fmt.Errorf("FetchNetworks: failed to unmarshal the network database: %v", err)
	}

	return &ndb, nil
}

func DeleteNetwork(ndbPath string, networkName string) error {

	var i int
	var ndb Ndb
	var found bool

	// Read the configuration file
	byteValue, err := ioutil.ReadFile(ndbPath)
	if err != nil {
		return fmt.Errorf("DeleteNetwork: failed to read the configuration file: %v", err)
	}

	err = json.Unmarshal(byteValue, &ndb)
	if err != nil {
		return fmt.Errorf("DeleteNetwork: failed to unmarshal the network configuration: %v", err)
	}

	// Find the network to delete
	for i = 0; i < len(ndb.Networks); i++ {
		if ndb.Networks[i].Name == networkName {
			ndb.Networks = append(ndb.Networks[:i], ndb.Networks[i+1:]...)
			found = true
			break
		}
	}

	if found == false {
		return fmt.Errorf("DeleteNetwork: failed to delete network: `%v`: not found", networkName)
	}

	marshaledJSON, err := json.MarshalIndent(ndb, "", " ")
	if err != nil {
		return fmt.Errorf("DeleteNetwork: failed to marshal the network configuration: %v", err)
	}

	err = ioutil.WriteFile(ndbPath, marshaledJSON, 0644)
	if err != nil {
		return fmt.Errorf("DeleteNetwork: failed to save the network configuration: %v", err)
	}

	return nil
}
