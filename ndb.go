package ndb

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
