package agent

import (
	"bufio"
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// NetworkCredentials is the network informations.
type NetworkCredentials struct {
	Name   string `json:"name"`
	APIsrv string `json:"api_srv"`
	PVkey  string `json:"pvkey"`
	Cert   string `json:"cert"`
	CAcert string `json:"cacert"`
}

// provInformation is the provisioning information contains in the prov link
type provInformation struct {
	Version    string
	APIsrv     string
	NetworkUID string
	NodeUID    string
	Key        string
}

// csrRequest is the Certificate Signing Request
type csrRequest struct {
	CSR      string `json:"csr"`
	ProvLink string `json:"provlink"`
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

// GetNetworkCred returns the credentials of the specified network name if the network exist
func GetNetworkCred(networkName string) (*NetworkCredentials, error) {

	var netConf Ndb

	// Read the configuration file
	byteValue, err := ioutil.ReadFile(GetNdbPath())
	if err != nil {
		return nil, fmt.Errorf("GetNetworkCred: failed to read the configuration file: %v\n", err)
	}

	err = json.Unmarshal(byteValue, &netConf)
	if err != nil {
		return nil, fmt.Errorf("GetNetworkCred: failed to unmarshal the network configuration: %v\n", err)
	}

	// Find the network in the list
	for i := 0; i < len(netConf.Networks); i++ {
		networkCred := netConf.Networks[i]
		if networkCred.Name == networkName {
			return &networkCred, nil
		}
	}

	// Nothing found
	return nil, nil
}

// DeleteNetwork delete the network specified in parameter
func DeleteNetwork(networkName string) error {

	var i int
	var ndb Ndb
	var found bool

	// Read the configuration file
	byteValue, err := ioutil.ReadFile(GetNdbPath())
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

	err = ioutil.WriteFile(GetNdbPath(), marshaledJSON, 0644)
	if err != nil {
		return fmt.Errorf("DeleteNetwork: failed to save the network configuration: %v", err)
	}

	return nil
}

// ProvisionNetwork provision a new network based on the provisioned linked
func ProvisionNetwork(provLink string, networkName string) error {

	var netConf Ndb
	var networkCred NetworkCredentials
	var provInfo provInformation
	var marshaledJSON []byte

	cred, _ := GetNetworkCred(networkName)
	if cred == nil {
		return fmt.Errorf("ProvisionNetwork: the network name already exist: %s\n", networkName)
	}

	Ldebug.Printf("provLink: %s\n", provLink)

	// Parse the provisioning link
	u, err := url.Parse(provLink)
	if err != nil {
		return fmt.Errorf("ProvisionNetwork: failed to parse the provisioning link: %v\n", err)
	}

	Ldebug.Printf("Parsed provisioning link: %v\n", u.RawQuery)

	values, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return fmt.Errorf("ProvisionNetwork: failed to parse the query string: %v\n", err)
	}

	// Extract the fields from the provisioning link
	// FIXME create a function that validate and return a provInfo
	provInfo.Version = values.Get("v")
	provInfo.APIsrv = values.Get("a")
	provInfo.NetworkUID = values.Get("w")
	provInfo.NodeUID = values.Get("n")
	provInfo.Key = values.Get("k")

	if provInfo.Version == "" {
		return fmt.Errorf("ProvisionNetwork: failed to find the version from the provisioning link")
	}
	if provInfo.APIsrv == "" {
		return fmt.Errorf("ProvisionNetwork: failed to find the API server from the provisioning link")
	}
	if provInfo.NetworkUID == "" {
		return fmt.Errorf("ProvisionNetwork: failed to find the network UID from the provisioning link")
	}
	if provInfo.NodeUID == "" {
		return fmt.Errorf("ProvisionNetwork: failed to find the node UID from the provisioning link")
	}
	if provInfo.Key == "" {
		return fmt.Errorf("ProvisionNetwork: failed to find the key from the provisioning link")
	}

	// Read the configuration into netConf
	data, err := ioutil.ReadFile(GetNdbPath())
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			// Since the file doesn't exist, we
			// initialize the netConf structure that will
			// be written to a new file
			netConf.Version = 1
		} else {
			return fmt.Errorf("ProvisionNetwork: failed to read the configuration file: %v\n", err)
		}
	} else {
		err = json.Unmarshal(data, &netConf)
		if err != nil {
			return fmt.Errorf("ProvisionNetwork: failed to unmarshal the network configuration: %v\n", err)
		}
	}

	// Generate a new public/private key pair
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("ProvisionNetwork: failed to generate new key pair: %v\n", err)
	}

	// Prepare a Certificate Signing Request
	name := pkix.Name{
		CommonName: "netvfy-agent",
	}

	csrTemplate := x509.CertificateRequest{
		Subject:            name,
		SignatureAlgorithm: x509.ECDSAWithSHA512,
	}

	csrCertificate, err := x509.CreateCertificateRequest(rand.Reader, &csrTemplate, privKey)
	if err != nil {
		return fmt.Errorf("ProvisionNetwork: failed to generate the Certificate Signing Request: %v\n", err)
	}

	csr := pem.EncodeToMemory(&pem.Block{
		Type: "CERTIFICATE REQUEST", Bytes: csrCertificate,
	})

	Ldebug.Printf("CSR: %s\n", csr)

	// Prepare the HTTP request asking to sign our CSR
	req := csrRequest{
		CSR:      string(csr),
		ProvLink: provLink,
	}

	jreq, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("ProvisionNetwork: failed to marshal the Certificate Signing Request request: %v\n", err)
	}

	Ldebug.Printf("CSR request: %s\n", jreq)

	timeout := time.Duration(5 * time.Second)
	client := http.Client{
		Timeout: timeout,
	}
	request, err := http.NewRequest("POST", "https://"+provInfo.APIsrv+"/v1/provisioning", bytes.NewBuffer(jreq))
	if err != nil {
		return fmt.Errorf("ProvisionNetwork: failed to create the http new request: %v\n", err)
	}
	request.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(request)
	if err != nil {
		return fmt.Errorf("ProvisionNetwork: failed to perform the http request: %v\n", err)
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("ProvisionNetwork: failed to read the query response: %v\n", err)
	}

	// Unmarshal the CSR response
	err = json.Unmarshal(body, &networkCred)
	if err != nil {
		return fmt.Errorf("ProvisionNetwork: failed to unmarshal the provisioning response: %v\n", err)
	}

	// If no network name was provided, ask for one
	networkCred.Name = networkName
	if networkCred.Name == "" {
		Linfo.Print("Enter the name of the new network: ")
		reader := bufio.NewReader(os.Stdin)
		// ReadString will block until the delimiter is entered
		networkCred.Name, err = reader.ReadString('\n')
		if err != nil {
			return fmt.Errorf("ProvisionNetwork: failed to read the entered network name: %v\n", err)
		}
		networkCred.Name = strings.TrimRight(networkCred.Name, "\r\n")
	}

	networkCred.APIsrv = provInfo.APIsrv

	// Convert private key in string format to be saved in the configuration file
	x509Encoded, _ := x509.MarshalECPrivateKey(privKey)
	pemEncoded := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: x509Encoded})
	networkCred.PVkey = string(pemEncoded)

	Ldebug.Printf("cert:\n%s\n", networkCred.Cert)
	Ldebug.Printf("CAcert:\n%s\n", networkCred.CAcert)

	netConf.Networks = append(netConf.Networks, networkCred)

	marshaledJSON, err = json.MarshalIndent(netConf, "", " ")
	if err != nil {
		return fmt.Errorf("ProvisionNetwork: failed to marshal the network configuration: %v\n", err)
	}

	os.MkdirAll(filepath.Dir(GetNdbPath()), os.ModePerm)
	err = ioutil.WriteFile(GetNdbPath(), marshaledJSON, 0644)
	if err != nil {
		return fmt.Errorf("ProvisionNetwork: failed to save the network configuration: %v\n", err)
	}

	return nil
}
