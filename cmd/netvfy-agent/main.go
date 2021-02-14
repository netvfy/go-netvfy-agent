package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"time"

	water "github.com/netvfy/tuntap"
)

type networkCredentials struct {
	Name   string `json:"name"`
	APIsrv string `json:"api_srv"`
	PVkey  string `json:"pvkey"`
	Cert   string `json:"cert"`
	CAcert string `json:"cacert"`
}

type netvfyConfig struct {
	Version  int                  `json:"version"`
	Networks []networkCredentials `json:"networks"`
}

type provInformation struct {
	Version    string
	APIsrv     string
	NetworkUID string
	NodeUID    string
	Key        string
}

type csrRequest struct {
	CSR      string `json:"csr"`
	ProvLink string `json:"provlink"`
}

type certNetInformation struct {
	Version    string
	Type       string
	NetworkUID string
	NodeUID    string
}

type netinfosRequest struct {
	Network string `json:"network"`
	Node    string `json:"node"`
}

type arrayControllerInfo struct {
	NetInfos []controllerInfo `json:"netinfos"`
}

type controllerInfo struct {
	Family string `json:"family"`
	Addr   string `json:"addr"`
	Port   string `json:"port"`
	Region string `json:"region"`
}

type nodeInformation struct {
	Action       string `json:"action"`
	LocalIPaddr  string `json:"local_ipaddr"`
	Sysname      string `json:"sysname"`
	LLaddr       string `json:"lladdr"`
	AgentVersion string `json:"agent_version"`
}

type switchInformation struct {
	Action  string `json:"action"`
	Addr    string `json:"addr"`
	Port    string `json:"port"`
	IPaddr  string `json:"ipaddr"`
	Netmask string `json:"netmask"`
}

type keepAlive struct {
	Action string `json:"action"`
}

type nvHdr struct {
	Length uint16
	Type   uint16
	Tmp    uint16
}

type switchInstance struct {
	info   switchInformation
	ctx    context.Context
	cancel context.CancelFunc
}

var dlog *log.Logger
var ilog *log.Logger
var elog *log.Logger

var gSwitch switchInstance
var gNetConfPath string
var utun *water.Interface
var vswitchConn *tls.Conn

var gMAC []byte

const utunName = "utun7"
const randomInternetIP = "8.8.8.8:80"

func genMAC() []byte {

	mac := make([]byte, 6)
	rand.Read(mac)

	// set the local bit
	// https://en.wikipedia.org/wiki/MAC_address#Universal_vs._local_(U/L_bit)
	mac[0] |= 0b00000010

	// make sure the last bit is not set
	// when the last bit is 0, it means the MAC is unicast
	// https://en.wikipedia.org/wiki/MAC_address#Unicast_vs._multicast_(I/G_bit)
	mac[0] &= 0b11111110

	return mac
}

func getOutboundIP() string {
	conn, err := net.Dial("udp", randomInternetIP)
	if err != nil {
		elog.Fatalf("failed get the outbound IP: %v\n", err)
	}
	defer conn.Close()

	localAddr := conn.LocalAddr().(*net.UDPAddr)

	return localAddr.IP.String()
}

func provisioning(provLink string, netLabel string) {

	var netConf netvfyConfig
	var networkCred networkCredentials
	var provInfo provInformation
	var marshaledJSON []byte

	// Parse the provisioning link
	u, err := url.Parse(provLink)
	if err != nil {
		elog.Fatalf("failed to parse the provisioning link: %v\n", err)
	}

	dlog.Printf("Parsed provisioning link: %v\n", u.RawQuery)

	values, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		elog.Fatalf("failed to parse the query string: %v\n", err)
	}

	// Extract the fields from the provisioning link
	provInfo.Version = values.Get("v")
	provInfo.APIsrv = values.Get("a")
	provInfo.NetworkUID = values.Get("w")
	provInfo.NodeUID = values.Get("n")
	provInfo.Key = values.Get("k")

	if provInfo.Version == "" {
		elog.Fatal("failed to find the version from the provisioning link")
	}
	if provInfo.APIsrv == "" {
		elog.Fatal("failed to find the API server from the provisioning link")
	}
	if provInfo.NetworkUID == "" {
		elog.Fatal("failed to find the network UID from the provisioning link")
	}
	if provInfo.NodeUID == "" {
		elog.Fatal("failed to find the node UID from the provisioning link")
	}
	if provInfo.Key == "" {
		elog.Fatal("failed to find the key from the provisioning link")
	}

	// Read the configuration into netConf
	data, err := ioutil.ReadFile(gNetConfPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			// Since the file doesn't exist, we
			// initialize the netConf structure that will
			// be written to a new file
			netConf.Version = 1
		} else {
			elog.Fatalf("failed to read the configuration file: %v\n", err)
		}
	} else {
		err = json.Unmarshal(data, &netConf)
		if err != nil {
			elog.Fatalf("failed to unmarshal the network configuration: %v\n", err)
		}
	}

	// Generate a new public/private key pair
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		elog.Fatalf("failed to generate new key pair: %v\n", err)
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
		elog.Fatalf("failed to generate the Certificate Signing Request: %v\n", err)
	}

	csr := pem.EncodeToMemory(&pem.Block{
		Type: "CERTIFICATE REQUEST", Bytes: csrCertificate,
	})

	dlog.Printf("CSR: %s\n", csr)

	// Prepare the HTTP request asking to sign our CSR
	req := csrRequest{
		CSR:      string(csr),
		ProvLink: provLink,
	}

	jreq, err := json.Marshal(req)
	if err != nil {
		elog.Fatalf("failed to marshal the Certificate Signing Request request: %v\n", err)
	}

	dlog.Printf("CSR request: %s\n", jreq)

	timeout := time.Duration(5 * time.Second)
	client := http.Client{
		Timeout: timeout,
	}
	request, err := http.NewRequest("POST", "https://"+provInfo.APIsrv+"/v1/provisioning", bytes.NewBuffer(jreq))
	if err != nil {
		elog.Fatalf("failed to create the http new request: %v\n", err)
	}
	request.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(request)
	if err != nil {
		elog.Fatalf("failed to perform the http request: %v\n", err)
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		elog.Fatalf("failed to read the query response: %v\n", err)
	}

	// Unmarshal the CSR response
	err = json.Unmarshal(body, &networkCred)
	if err != nil {
		elog.Fatalf("failed to unmarshal the provisioning response: %v\n", err)
	}

	// If no network name was provided, ask for one
	networkCred.Name = netLabel
	if networkCred.Name == "" {
		ilog.Print("Enter the name of the new network: ")
		reader := bufio.NewReader(os.Stdin)
		// ReadString will block until the delimiter is entered
		networkCred.Name, err = reader.ReadString('\n')
		if err != nil {
			elog.Fatalf("failed to read the entered network name: %v\n", err)
		}
		networkCred.Name = strings.TrimRight(networkCred.Name, "\r\n")
	}

	networkCred.APIsrv = provInfo.APIsrv

	// Convert private key in string format to be saved in the configuration file
	x509Encoded, _ := x509.MarshalECPrivateKey(privKey)
	pemEncoded := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: x509Encoded})
	networkCred.PVkey = string(pemEncoded)

	dlog.Printf("cert:\n%s\n", networkCred.Cert)
	dlog.Printf("CAcert:\n%s\n", networkCred.CAcert)

	netConf.Networks = append(netConf.Networks, networkCred)

	marshaledJSON, err = json.MarshalIndent(netConf, "", " ")
	if err != nil {
		elog.Fatalf("failed to marshal the network configuration: %v\n", err)
	}

	err = ioutil.WriteFile(gNetConfPath, marshaledJSON, 0644)
	if err != nil {
		elog.Fatalf("failed to save the network configuration: %v\n", err)
	}
}

func connController(ctx context.Context, cancel context.CancelFunc, ctrlInfo *controllerInfo, config *tls.Config) {

	var switchInfo switchInformation

	// Establish the TLS connection to the controller
	conn, err := tls.Dial("tcp", ctrlInfo.Addr+":"+ctrlInfo.Port, config)
	if err != nil {
		elog.Printf("failed to dial the controller %s:%s: %v", ctrlInfo.Addr, ctrlInfo.Port, err)
		return
	}
	defer conn.Close()

	dlog.Printf("connected to the controller: %v", conn.RemoteAddr())

	// Print the certificate information of the controller
	state := conn.ConnectionState()
	for _, cert := range state.PeerCertificates {
		dlog.Printf("controller: issuer Name: %s\n", cert.Issuer)
		dlog.Printf("controller: expiry: %s\n", cert.NotAfter.Format("2006-January-02"))
		dlog.Printf("controller: common Name: %s\n", cert.Issuer.CommonName)
	}
	// Print the state of the connection
	dlog.Printf("controller: handshake: %v\n", state.HandshakeComplete)
	dlog.Printf("controller: mutual: %v\n", state.NegotiatedProtocolIsMutual)

	// Create a node info object with our information
	outboundIP := getOutboundIP()
	mac := net.HardwareAddr(gMAC)

	uname := ""
	cmd := exec.Command("uname", "-a")
	var out bytes.Buffer
	cmd.Stdout = &out
	err = cmd.Run()
	if err != nil {
		elog.Printf("failed to get `uname -a`: %v\n", err)
	} else {
		uname = out.String()
	}

	dlog.Printf("outbound IP: %s\n", outboundIP)
	dlog.Printf("mac address: %s\n", mac.String())
	dlog.Printf("uname -a: %s\n", uname)

	nodeInfo := &nodeInformation{
		Action:       "nodeinfo",
		LocalIPaddr:  outboundIP,
		Sysname:      uname,
		LLaddr:       mac.String(),
		AgentVersion: "go-0.1c1",
	}

	jnodeInfo, err := json.Marshal(nodeInfo)
	if err != nil {
		dlog.Printf("failed to marshal node info request: %v\n", err)
		return
	}

	// Send our information to the controller
	_, err = io.WriteString(conn, string(jnodeInfo)+"\n")
	if err != nil {
		dlog.Printf("failed to send the node info to the controller: %v", err)
		return
	}

	// Prepare the keep alive ticker
	keepAlive := &keepAlive{
		Action: "keepalive",
	}

	jkeepAlive, err := json.Marshal(keepAlive)
	if err != nil {
		dlog.Printf("failed to marshal the keep alive: %v\n", err)
		return
	}

	// Every second we seend a keep alive to the controller
	ticker := time.NewTicker(1 * time.Second)
	done := make(chan bool)
	go func() {
		for {
			select {
			case <-done:
				return
			case <-ticker.C:
				_, err = io.WriteString(conn, string(jkeepAlive)+"\n")
				if err != nil {
					// the agent got disconnected from the controller
					ticker.Stop()
					done <- true
					return
				}
			}
		}
	}()

	for {
		select {
		case <-done:
			// ticker detected a disconnect form the controller
			return
		default:
			break
		}

		err = json.NewDecoder(conn).Decode(&switchInfo)
		if err != nil {
			dlog.Printf("failed to unmarshal the switch info: %v\n", err)
			return
		}

		if switchInfo.Action == "netinfos" &&
			(gSwitch.info.Addr != switchInfo.Addr ||
				gSwitch.info.Port != switchInfo.Port ||
				gSwitch.info.IPaddr != switchInfo.IPaddr ||
				gSwitch.info.Netmask != switchInfo.Netmask) {

			dlog.Printf("Addr: %s -- %s\n", gSwitch.info.Addr, switchInfo.Addr)
			dlog.Printf("Port: %s -- %s\n", gSwitch.info.Port, switchInfo.Port)
			dlog.Printf("IPaddr: %s -- %s\n", gSwitch.info.IPaddr, switchInfo.IPaddr)
			dlog.Printf("Netmask: %s -- %s\n", gSwitch.info.Netmask, switchInfo.Netmask)

			gSwitch.info.Addr = switchInfo.Addr
			gSwitch.info.Port = switchInfo.Port
			gSwitch.info.IPaddr = switchInfo.IPaddr
			gSwitch.info.Netmask = switchInfo.Netmask

			// FIXME
			// replace this section once these functions are included in the tuntap library
			cmd := exec.Command("ifconfig", utunName, gSwitch.info.IPaddr, gSwitch.info.IPaddr, "netmask", gSwitch.info.Netmask)
			dlog.Printf("%s\n", cmd.String())
			stderr, err := cmd.StderrPipe()
			err = cmd.Start()
			if err != nil {
				elog.Fatalf("failed to apply ifconfig on %v: %v\n", utunName, err)
			}
			slurp, _ := ioutil.ReadAll(stderr)
			if err := cmd.Wait(); err != nil {
				dlog.Printf("stderr: %v\n", slurp)
				dlog.Fatalf("failed to apply ifconfig on %v: %v\n", utunName, err)
			}

			// We want to extract the subnet from the IP and netmask
			// 192.168.0.1 & 255.255.0.0 --> 192.168.0.0
			ipv4addr := net.ParseIP(gSwitch.info.IPaddr)
			ipv4netmask := (net.ParseIP(gSwitch.info.Netmask)).To4()
			mask := net.IPv4Mask(ipv4netmask[0], ipv4netmask[1], ipv4netmask[2], ipv4netmask[3])
			subnet := ipv4addr.Mask(net.CIDRMask(mask.Size()))

			cmd = exec.Command("route", "add", "-net", subnet.String(), gSwitch.info.IPaddr, gSwitch.info.Netmask)
			dlog.Printf("%v\n", cmd.String())
			stderr, err = cmd.StderrPipe()
			err = cmd.Start()
			if err != nil {
				elog.Fatalf("failed to add new route on %v: %v", utunName, err)
			}
			slurp, _ = ioutil.ReadAll(stderr)
			if err := cmd.Wait(); err != nil {
				dlog.Printf("stderr: %v\n", slurp)
				dlog.Fatalf("failed to add new route on %v: %v\n", utunName, err)
			}

			// If switch is potentially running let's cancel it
			if gSwitch.cancel != nil {
				dlog.Printf("close the connection to the vswitch\n")
				gSwitch.cancel()
				// Wait for the switch to exit
				if gSwitch.ctx != nil {
					<-gSwitch.ctx.Done()
				}
				gSwitch.cancel = nil
				gSwitch.ctx = nil
			}
		}

		// If the connection to the vswitch is not established, start it
		if gSwitch.ctx == nil {
			gSwitch.ctx, gSwitch.cancel = context.WithCancel(context.Background())
			dlog.Printf("start the connection to the vswitch\n")
			go connSwitch(gSwitch.ctx, gSwitch.cancel, config)
		}

		// Clear the content
		// FIXME use a generic var to switch on the 'action' field
		switchInfo = switchInformation{}
		time.Sleep(1 * time.Second)
	}
}

func connSwitch(ctx context.Context, cancel context.CancelFunc, config *tls.Config) {

	var done chan bool
	var ticker *time.Ticker
	var keepaliveBuf bytes.Buffer
	var nvhdr *nvHdr
	var state tls.ConnectionState
	var offset int = 0

	frameBuf := make([]byte, 2000)

	defer func() {
		time.Sleep(3 * time.Second)
		cancel()
		gSwitch.cancel = nil
		gSwitch.ctx = nil
	}()

	// Establish the TLS connection to the vswitch
	var err error
	vswitchConn, err = tls.Dial("tcp", gSwitch.info.Addr+":"+gSwitch.info.Port, config)
	if err != nil {
		elog.Printf("failed to dial the vswitch: %v", err)
		return
	}
	defer vswitchConn.Close()

	dlog.Printf("connected to the vswitch: %v", vswitchConn.RemoteAddr())

	// Print the certificate information of the vswitch
	state = vswitchConn.ConnectionState()
	for _, cert := range state.PeerCertificates {
		dlog.Printf("vswitch: issuer Name: %s\n", cert.Issuer)
		dlog.Printf("vswitch: expiry: %s \n", cert.NotAfter.Format("2006-January-02"))
		dlog.Printf("vswitch: common Name: %s \n", cert.Issuer.CommonName)
	}
	// Pint the state of the connection
	dlog.Printf("vswich: handshake: %v\n", state.HandshakeComplete)
	dlog.Printf("vswitch: client: mutual: %v\n", state.NegotiatedProtocolIsMutual)

	// Prepare the keep alive ticker
	nvhdr = &nvHdr{
		Length: 4,
		Type:   0,
	}

	binary.Write(&keepaliveBuf, binary.BigEndian, nvhdr)

	// Every second we send a keep alive to the vswitch
	ticker = time.NewTicker(1 * time.Second)
	done = make(chan bool)
	go func() {
		for {
			select {
			case <-ctx.Done():
				// the vswitch is done
				dlog.Printf("vswitch connection closing, context is done\n")
				return
				// the ticker is done
			case <-done:
				dlog.Printf("vswitch connection closing, ticker is done\n")
				return
			case <-ticker.C:
				_, err := vswitchConn.Write(keepaliveBuf.Bytes())
				if err != nil {
					dlog.Printf("got disconnected from the switch: %v\n", err)
					// the agent got disconnected from the vswitch
					ticker.Stop()
					done <- true
					return
				}
			}
		}
	}()

	for {
		select {
		case <-done:
			// ticker detected a disconnect form the controller
			return
		default:
			break
		}

		n, err := vswitchConn.Read(frameBuf[offset:])
		if err != nil {
			dlog.Printf("failed to read from vswitch: %v\n", err)
			return
		}

		// Move the offset after we've read more bytes into the buffer
		offset += n
		// Verify we've read enough bytes to make sense of our custom header
		if offset < 4 {
			continue
		}

		// Extract the length
		length := binary.BigEndian.Uint16(frameBuf[0:])
		// Check if the length is valid
		if length < 2 {
			return
		}
		// Check if the length is not bigger than our buffer
		if length > uint16(cap(frameBuf)) {
			return
		}

		// If we don't have the complete payload yet, we skip the next part
		if uint32(offset) < uint32(2+length) {
			continue
		}

		// Extract the type
		nvType := binary.BigEndian.Uint16(frameBuf[2:])

		switch nvType {
		case 0:
			// We just received a keep alive from the server
			break
		case 1:
			// We just received an ethernet frame from the server
			dlog.Printf("length: %d -- type: %d\n", length, nvType)

			dlog.Printf("DST MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
				frameBuf[4:5],
				frameBuf[5:6],
				frameBuf[6:7],
				frameBuf[7:8],
				frameBuf[8:9],
				frameBuf[9:10])

			dlog.Printf("SRC MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
				frameBuf[10:11],
				frameBuf[11:12],
				frameBuf[12:13],
				frameBuf[13:14],
				frameBuf[14:15],
				frameBuf[15:16])

			etherType := binary.BigEndian.Uint16(frameBuf[16:18])
			dlog.Printf("Ethertype %04x\n", etherType)

			// ARP -> 0x0806
			// IP  -> 0x0800

			// FIXME: handle fragmented frames
			b, err := utun.Write(frameBuf[4+14 : offset])
			if err != nil {
				elog.Printf("failed to write to the utun device: %v\n", err)
			}
			dlog.Printf("wrote %d bytes to the utun device\n", b)

		default:
			return
		}

		offset = 0
	}
}

func connectNetwork(networkName string) {

	var certNetInfo certNetInformation
	var networkCred networkCredentials
	var arrayCtrlInfo arrayControllerInfo
	var netConf netvfyConfig
	var i int

	// Read the configuration file
	byteValue, err := ioutil.ReadFile(gNetConfPath)
	if err != nil {
		elog.Fatalf("failed to read the configuration file: %v\n", err)
	}

	err = json.Unmarshal(byteValue, &netConf)
	if err != nil {
		elog.Fatalf("failed to unmarshal the network configuration: %v\n", err)
	}

	// Find the network in the list
	for i = 0; i < len(netConf.Networks); i++ {
		networkCred = netConf.Networks[i]
		if networkCred.Name == networkName {
			break
		}
	}

	if i >= len(netConf.Networks) {
		elog.Fatalf("failed to find the selected network: %v\n", networkName)
	}

	dlog.Printf("Name: %s\n", networkCred.Name)
	dlog.Printf("Cert: %s\n", networkCred.Cert)
	dlog.Printf("CAcert: %s\n", networkCred.CAcert)
	dlog.Printf("PVkey: %s\n", networkCred.PVkey)

	// Parse the Certificate and Private key to form the tls Certificate
	tlsCert, err := tls.X509KeyPair([]byte(networkCred.Cert), []byte(networkCred.PVkey))

	// Parse the certificate PEM to create an x509 certificate object
	// that will allow us to extract the Subject field
	block, _ := pem.Decode([]byte(networkCred.Cert))
	if block == nil {
		elog.Fatal("failed to parse the certificate in PEM format")
	}
	x509cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		elog.Fatalf("failed to convert the certificate to x509 format: %v\n", err)
	}

	dlog.Printf("Certificate Subject: %v\n", x509cert.Subject)

	// Parse the network information from the Subject
	values, err := url.ParseQuery(strings.TrimLeft(x509cert.Subject.String(), "CN="))
	if err != nil {
		elog.Fatalf("failed to parse the network information from the certificate subject: %v\n", err)
	}

	certNetInfo.Version = values.Get("v")
	certNetInfo.Type = values.Get("t")
	certNetInfo.NetworkUID = values.Get("w")
	certNetInfo.NodeUID = values.Get("n")

	if certNetInfo.Version == "" {
		elog.Fatal("failed to find the version from the certificate subject")
	}
	if certNetInfo.Type == "" {
		elog.Fatal("failed to find the type from the certificate subject")
	}
	if certNetInfo.NetworkUID == "" {
		elog.Fatal("failed to find the network UID from the certificate subject")
	}
	if certNetInfo.NodeUID == "" {
		elog.Fatal("failed to find the node UID from the certificate subject")
	}

	// Setup the tls Configuration, add the trusted CAcert
	// to the trusted pool
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM([]byte(networkCred.CAcert))

	config := tls.Config{
		Certificates:       []tls.Certificate{tlsCert},
		InsecureSkipVerify: true,
		ServerName:         certNetInfo.NetworkUID,
		RootCAs:            caCertPool,
	}

	// Build a json request containing the networkUID
	// and the networkUID.
	netinfosReq := netinfosRequest{
		Network: certNetInfo.NetworkUID,
		Node:    certNetInfo.NodeUID,
	}

	jnetinfosReq, err := json.Marshal(netinfosReq)
	if err != nil {
		elog.Fatalf("failed to marshal the network info request: %v\n", err)
	}

	dlog.Printf("network info request: %s\n", jnetinfosReq)

	// Setup the http request that will carry our json request
	timeout := time.Duration(5 * time.Second)
	client := http.Client{
		Timeout: timeout,
	}

	request, err := http.NewRequest("POST", "https://"+networkCred.APIsrv+"/v1/netinfos", bytes.NewBuffer(jnetinfosReq))
	if err != nil {
		elog.Printf("failed to create a new https request: %v\n", err)
		return
	}
	request.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(request)
	if err != nil {
		elog.Printf("failed network info request: %v\n", err)
		return
	}
	defer resp.Body.Close()

	// Read the response to our request
	buf, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		elog.Printf("failed to parse network info response: %v\n", err)
		return
	}

	dlog.Printf("netinfos: %v\n", string(buf))

	err = json.Unmarshal(buf, &arrayCtrlInfo)
	if err != nil {
		elog.Fatalf("failed to unmarshal the controller information: %v\n", err)
	}

	if len(arrayCtrlInfo.NetInfos) <= 0 {
		elog.Fatalf("failed to receive the controller information\n")
	}

	dlog.Printf("result: %v\n", arrayCtrlInfo)

	dlog.Printf("ctrlInfo.Family: %s\n", arrayCtrlInfo.NetInfos[0].Family)
	dlog.Printf("ctrlInfo.Addr: %s\n", arrayCtrlInfo.NetInfos[0].Addr)
	dlog.Printf("ctrlInfo.Port: %s\n", arrayCtrlInfo.NetInfos[0].Port)
	dlog.Printf("ctrlInfo.Region: %s\n", arrayCtrlInfo.NetInfos[0].Region)

	ctx, cancel := context.WithCancel(context.Background())
	connController(ctx, cancel, &arrayCtrlInfo.NetInfos[0], &config)
}

func deleteNetwork(networkName string) {

	var netConf netvfyConfig
	var found bool
	var i int

	// Read the configuration file
	byteValue, err := ioutil.ReadFile(gNetConfPath)
	if err != nil {
		elog.Fatalf("failed to read the configuration file: %v\n", err)
	}

	err = json.Unmarshal(byteValue, &netConf)
	if err != nil {
		elog.Fatalf("failed to unmarshal the network configuration: %v\n", err)
	}

	// Find the network to delete
	for i = 0; i < len(netConf.Networks); i++ {
		if netConf.Networks[i].Name == networkName {
			netConf.Networks = append(netConf.Networks[:i], netConf.Networks[i+1:]...)
			found = true
			break
		}
	}

	if found == false {
		elog.Fatalf("failed to delete network `%v`: not found\n", networkName)
	}

	marshaledJSON, err := json.MarshalIndent(netConf, "", " ")
	if err != nil {
		elog.Fatalf("failed to marshal the network configuration: %v\n", err)
	}

	err = ioutil.WriteFile(gNetConfPath, marshaledJSON, 0644)
	if err != nil {
		elog.Fatalf("failed to save the network configuration: %v\n", err)
	}

}

func listNetworks() {

	var netConf netvfyConfig
	var i int

	// Read the configuration file
	byteValue, err := ioutil.ReadFile(gNetConfPath)
	if err != nil {
		elog.Fatalf("failed to read the configuration file: %v\n", err)
	}

	err = json.Unmarshal(byteValue, &netConf)
	if err != nil {
		elog.Fatalf("failed to unmarshal the network configuration: %v\n", err)
	}

	ilog.Printf("Provisioned Networks:\n")
	// Find the network in the list
	for i = 0; i < len(netConf.Networks); i++ {
		ilog.Printf("\t%s\n", netConf.Networks[i].Name)
	}
}

func main() {

	provLink := flag.String("k", "", "Attach the node to the network [provisioning key]")
	netLabel := flag.String("n", "", "Specify the label of the provisioned node [to use with -k]")
	list := flag.Bool("l", false, "List networks")
	connect := flag.String("c", "", "Connect [network name]")
	delete := flag.String("d", "", "Delete [network name]")
	verbose := flag.Bool("v", false, "verbose")

	flag.Parse()

	// Enable debug log level
	var dlogOut io.Writer = ioutil.Discard
	if *verbose == true {
		dlogOut = os.Stdout
	}

	dlog = log.New(dlogOut, "debug: ", log.Ldate|log.Ltime|log.Lshortfile)
	ilog = log.New(os.Stdout, "", 0)
	elog = log.New(os.Stdout, "error: ", log.Ldate|log.Ltime|log.Lshortfile)

	// FIXME make it work on Windows too
	gNetConfPath = os.Getenv("HOME") + "/.config/netvfy/nvagent.json"

	if *provLink != "" {
		provisioning(*provLink, *netLabel)
		return
	} else if *list == true {
		listNetworks()
	} else if *connect != "" {

		gMAC = genMAC()

		config := water.Config{
			DeviceType: water.TUN,
		}
		var err error
		config.Name = utunName
		utun, err = water.New(config)
		if err != nil {
			elog.Fatalf("failed to initialize the %s interface: %v\n", utunName, err)
		}

		go func() {
			frameBuf := make([]byte, 2000)
			for {
				n, err := utun.Read(frameBuf[18:])
				if err != nil {
					elog.Printf("failed to read from %s: %v\n", utunName, err)
				}
				dlog.Printf("read %d bytes from %s\n", n, utunName)

				// nvHeader lenght value
				binary.BigEndian.PutUint16(frameBuf[0:2], uint16(n+14+2))
				// nvHeader type frame
				binary.BigEndian.PutUint16(frameBuf[2:4], 1)

				// DST MAC address
				binary.BigEndian.PutUint16(frameBuf[4:6], 0x9a36)
				binary.BigEndian.PutUint16(frameBuf[6:8], 0x31ee)
				binary.BigEndian.PutUint16(frameBuf[8:10], 0xe9d4)

				// SRC MAC address
				copy(frameBuf[10:16], gMAC[0:6])

				// EtherType IP
				binary.BigEndian.PutUint16(frameBuf[16:18], 0x0800)

				b, err := vswitchConn.Write(frameBuf[0 : n+14+4])
				if err != nil {
					elog.Printf("failed to write frame to %s\n", utunName)
				}
				dlog.Printf("wrote %d bytes to %s\n", b, utunName)
			}
		}()

		for {
			connectNetwork(*connect)
			time.Sleep(3 * time.Second)
		}
	} else if *delete != "" {
		deleteNetwork(*delete)
	} else {
		flag.PrintDefaults()
	}
}
