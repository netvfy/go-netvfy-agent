package agent

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"os/exec"
	"strings"
	"time"

	water "github.com/netvfy/tuntap"
)

type nodeInformation struct {
	Action       string `json:"action"`
	LocalIPaddr  string `json:"local_ipaddr"`
	Sysname      string `json:"sysname"`
	LLaddr       string `json:"lladdr"`
	AgentVersion string `json:"agent_version"`
}

type netinfosRequest struct {
	Network string `json:"network"`
	Node    string `json:"node"`
}

type controllerInfo struct {
	Family string `json:"family"`
	Addr   string `json:"addr"`
	Port   string `json:"port"`
	Region string `json:"region"`
}

type arrayControllerInfo struct {
	NetInfos []controllerInfo `json:"netinfos"`
}

type certNetInformation struct {
	Version    string
	Type       string
	NetworkUID string
	NodeUID    string
}

type switchInformation struct {
	Action  string `json:"action"`
	Addr    string `json:"addr"`
	Port    string `json:"port"`
	IPaddr  string `json:"ipaddr"`
	Netmask string `json:"netmask"`
}

type switchInstance struct {
	info   switchInformation
	ctx    context.Context
	cancel context.CancelFunc
}

type keepAlive struct {
	Action string `json:"action"`
}

type nvHdr struct {
	Length uint16
	Type   uint16
}

var gMAC []byte
var gSwitch switchInstance
var utun *water.Interface
var vswitchConn *tls.Conn

var (
	// arpQueue of waiting frames that is global to main.
	arpQueue *ARPQueue
	// arpTable is global to main.
	arpTable *ArpTable
)

// queueMax is hard limit of arpQueue entries.
const arpQueueMax = 50
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
		Lerror.Fatalf("failed get the outbound IP: %v\n", err)
	}
	defer conn.Close()

	localAddr := conn.LocalAddr().(*net.UDPAddr)

	return localAddr.IP.String()
}

func ReadUTUN() {
	//[ nvheader (4) | (14) ETHERNET_STUFF | IP PACKET (...)]
	frameBuf := make([]byte, 2000)
	for {
		n, err := utun.Read(frameBuf[4+14:])
		if err != nil {
			Lerror.Printf("failed to read from %s: %v\n", utunName, err)
		}
		Ldebug.Printf("read %d bytes from %s\n", n, utunName)

		if vswitchConn == nil {
			continue
		}

		// nvHeader length value
		binary.BigEndian.PutUint16(frameBuf[0:2], uint16(2+14+n))
		// nvHeader type frame
		binary.BigEndian.PutUint16(frameBuf[2:4], 1)
		// src MAC address
		copy(frameBuf[10:16], gMAC[0:6])

		dstIP := net.IPv4(frameBuf[34], frameBuf[35], frameBuf[36], frameBuf[37]).To4()
		entry, found, err := arpTable.Get(dstIP.String())
		if err != nil {
			Lerror.Printf("unable to retrieve ARP entry for %v: %v", dstIP.String(), err)
		}

		if found {
			// We found the destination MAC in the ARP table, continue to craft
			// the ethernet header of the IP packet.

			// DST MAC address
			copy(frameBuf[4:10], entry.Mac)
			// EtherType IP
			binary.BigEndian.PutUint16(frameBuf[16:18], TypeIPv4)

			b, err := vswitchConn.Write(frameBuf[0 : 4+14+n])
			if err != nil {
				Lerror.Printf("failed to write frame to %s\n", utunName)
			}
			Ldebug.Printf("wrote %d bytes to vswitch\n", b)

		} else {

			// TODO: Queue ethernet frame while ARP is being resolving the dst MAC address

			//		Ldebug.Printf("Sending an ARP request !\n")
			sendBuf, err := GenerateARPRequest(arpTable, gMAC, dstIP.String(), gSwitch.info.IPaddr)
			if err != nil {
				Lerror.Printf("unable to generate ARP request: %v", err)
			}

			b, err := vswitchConn.Write(sendBuf)
			if err != nil {
				Lerror.Printf("failed to write frame to the switch: %v\n", err)
			}
			Ldebug.Printf("wrote %d bytes to vswitch\n", b)

		}
	}
}

func connSwitch(ctx context.Context, cancel context.CancelFunc, config *tls.Config) {

	var done chan bool
	var ticker *time.Ticker
	var keepaliveBuf bytes.Buffer
	var nvhdr *nvHdr
	var state tls.ConnectionState
	var offset int = 0
	var n int = 0

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
		Lerror.Printf("failed to dial the vswitch: %v", err)
		return
	}
	defer vswitchConn.Close()

	Ldebug.Printf("connected to the vswitch: %v", vswitchConn.RemoteAddr())

	// Print the certificate information of the vswitch
	state = vswitchConn.ConnectionState()
	for _, cert := range state.PeerCertificates {
		Ldebug.Printf("vswitch: issuer Name: %s\n", cert.Issuer)
		Ldebug.Printf("vswitch: expiry: %s \n", cert.NotAfter.Format("2006-January-02"))
		Ldebug.Printf("vswitch: common Name: %s \n", cert.Issuer.CommonName)
	}
	// Pint the state of the connection
	Ldebug.Printf("vswich: handshake: %v\n", state.HandshakeComplete)
	Ldebug.Printf("vswitch: client: mutual: %v\n", state.NegotiatedProtocolIsMutual)

	// Prepare the keep alive ticker
	nvhdr = &nvHdr{
		Length: 2,
		Type:   0,
	}

	binary.Write(&keepaliveBuf, binary.BigEndian, nvhdr)

	// Generate the Ethernet header --------------------
	garpBuf := make([]byte, 2+14+28)
	// nvHeader length value
	binary.BigEndian.PutUint16(garpBuf[0:2], uint16(2+14+28))
	// nvHeader type frame
	binary.BigEndian.PutUint16(garpBuf[2:4], 1)
	// src MAC address
	copy(frameBuf[10:16], gMAC[0:6])
	// DST MAC address

	bcastmac := []byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}
	copy(frameBuf[4:10], bcastmac)
	// EtherType IP
	binary.BigEndian.PutUint16(frameBuf[16:18], TypeARP)

	// Generate and send gratutious ARP here
	srcMAC := net.HardwareAddr(gMAC)

	srcIP := net.ParseIP(gSwitch.info.IPaddr)
	dstIP := net.ParseIP(gSwitch.info.IPaddr)

	garp, err := GenerateARPRequest(nil, srcMAC, dstIP.String(), srcIP.String())
	if err != nil {
		Lerror.Printf("failed to generate ARP request: %v", err)
	}

	copy(garpBuf[4+14:], garp)
	vswitchConn.Write(garpBuf)

	///---------------------------------------------------

	// Every second we send a keep alive to the vswitch
	ticker = time.NewTicker(1 * time.Second)
	done = make(chan bool)
	go func() {
		for {
			select {
			case <-ctx.Done():
				// the vswitch is done
				Ldebug.Printf("vswitch connection closing, context is done\n")
				return
				// the ticker is done
			case <-done:
				Ldebug.Printf("vswitch connection closing, ticker is done\n")
				return
			case <-ticker.C:
				_, err := vswitchConn.Write(keepaliveBuf.Bytes())
				if err != nil {
					Ldebug.Printf("got disconnected from the switch: %v\n", err)
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
		}

		if offset == 0 {
			// Read the NV header first.
			n, err := io.ReadFull(vswitchConn, frameBuf[0:4])
			if err == io.ErrUnexpectedEOF || err == io.ErrShortBuffer {
				Ldebug.Printf("failed to read NV header from vswitch: %v\n", err)
				return
			}
			// Move the offset after we've read more bytes into the buffer
			offset += n
		}

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

		if offset >= 4 && length > 2 { // try to read the whole frame
			n, err = io.ReadFull(vswitchConn, frameBuf[offset:offset+int(length)-2-offset+4])
			if err == io.ErrUnexpectedEOF || err == io.ErrShortBuffer {
				Ldebug.Printf("failed to read payload from vswitch: %v\n", err)
				return
			}
			// Move the offset after we've read more bytes into the buffer
			offset += n
		}

		// If we don't have the complete payload yet, we skip the next part
		if uint32(offset) < uint32(2+length) {
			continue
		}

		// Extract the type
		nvType := binary.BigEndian.Uint16(frameBuf[2:])

		switch nvType {
		case 0:
			// We just received a keep alive from the server, do nothing
		case 1:
			// We just received an ethernet frame from the server
			Ldebug.Printf("length: %d -- type: %d\n", length, nvType)

			Ldebug.Printf("DST MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
				frameBuf[4:5],
				frameBuf[5:6],
				frameBuf[6:7],
				frameBuf[7:8],
				frameBuf[8:9],
				frameBuf[9:10])

			Ldebug.Printf("SRC MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
				frameBuf[10:11],
				frameBuf[11:12],
				frameBuf[12:13],
				frameBuf[13:14],
				frameBuf[14:15],
				frameBuf[15:16])

			etherType := binary.BigEndian.Uint16(frameBuf[16:18])
			Ldebug.Printf("Ethertype %04x\n", etherType)
			if etherType == TypeARP {

				oper := binary.BigEndian.Uint16(frameBuf[24:26])

				sha, _ := net.ParseMAC("00:00:00:00:00:00")
				copy(sha, frameBuf[26:32])

				spa := net.IPv4(frameBuf[32], frameBuf[33], frameBuf[34], frameBuf[35])

				tha, _ := net.ParseMAC("00:00:00:00:00:00")
				copy(tha, frameBuf[36:42])

				tpa := net.IPv4(frameBuf[42], frameBuf[43], frameBuf[44], frameBuf[45]).To4()

				Ldebug.Printf("ARP HTYPE: %x\n", binary.BigEndian.Uint16(frameBuf[18:20]))
				Ldebug.Printf("ARP PTYPE: %x\n", binary.BigEndian.Uint16(frameBuf[20:22]))
				Ldebug.Printf("ARP HLEN: %x\n", binary.BigEndian.Uint16(frameBuf[22:24])>>8)
				Ldebug.Printf("ARP PLEN: %x\n", binary.BigEndian.Uint16(frameBuf[22:24])&0x0F)
				Ldebug.Printf("ARP OPER: %x\n", oper)
				Ldebug.Printf("ARP SHA: %s\n", sha.String())
				Ldebug.Printf("ARP SPA: %s\n", spa.String())
				Ldebug.Printf("ARP THA: %s\n", tha)
				Ldebug.Printf("ARP TPA: %s\n", tpa.String())

				if oper == OperationReply {
					Ldebug.Printf("Received ARP response\n")
					// We received an ARP response
					err := arpTable.Update(spa.String(), sha)
					if err != nil {
						Lerror.Printf("unable to update ARP entry: %v", err)
					}
				} else if oper == OperationRequest {
					Ldebug.Printf("Received ARP request\n")
					// We received an ARP request, send a response
					sendBuf := GenerateARPReply(gMAC[0:6], sha, tpa, spa)

					b, err := vswitchConn.Write(sendBuf)
					if err != nil {
						Lerror.Printf("failed to write frame to %s\n", utunName)
					}
					Ldebug.Printf("wrote %d bytes to vswitch\n", b)
				}
			} else {
				// IP  -> 0x0800
				b, err := utun.Write(frameBuf[4+14 : offset])
				if err != nil {
					Lerror.Printf("failed to write to the utun device: %v\n", err)
				}
				Ldebug.Printf("wrote %d bytes to the utun device\n", b)
			}
		default:
			return
		}

		offset = 0
		n = 0
	}
}

func connController(ctx context.Context, cancel context.CancelFunc, ctrlInfo *controllerInfo, config *tls.Config) {

	var switchInfo switchInformation

	// Establish the TLS connection to the controller
	conn, err := tls.Dial("tcp", ctrlInfo.Addr+":"+ctrlInfo.Port, config)
	if err != nil {
		Lerror.Printf("failed to dial the controller %s:%s: %v", ctrlInfo.Addr, ctrlInfo.Port, err)
		return
	}
	defer conn.Close()

	Ldebug.Printf("connected to the controller: %v", conn.RemoteAddr())

	// Print the certificate information of the controller
	state := conn.ConnectionState()
	for _, cert := range state.PeerCertificates {
		Ldebug.Printf("controller: issuer Name: %s\n", cert.Issuer)
		Ldebug.Printf("controller: expiry: %s\n", cert.NotAfter.Format("2006-January-02"))
		Ldebug.Printf("controller: common Name: %s\n", cert.Issuer.CommonName)
	}
	// Print the state of the connection
	Ldebug.Printf("controller: handshake: %v\n", state.HandshakeComplete)
	Ldebug.Printf("controller: mutual: %v\n", state.NegotiatedProtocolIsMutual)

	// Create a node info object with our information
	outboundIP := getOutboundIP()
	mac := net.HardwareAddr(gMAC)

	uname := ""
	cmd := exec.Command("uname", "-a")
	var out bytes.Buffer
	cmd.Stdout = &out
	err = cmd.Run()
	if err != nil {
		Lerror.Printf("failed to get `uname -a`: %v\n", err)
	} else {
		uname = out.String()
	}

	Ldebug.Printf("outbound IP: %s\n", outboundIP)
	Ldebug.Printf("mac address: %s\n", mac.String())
	Ldebug.Printf("uname -a: %s\n", uname)

	nodeInfo := &nodeInformation{
		Action:       "nodeinfo",
		LocalIPaddr:  outboundIP,
		Sysname:      uname,
		LLaddr:       mac.String(),
		AgentVersion: "go-0.1c1",
	}

	jnodeInfo, err := json.Marshal(nodeInfo)
	if err != nil {
		Ldebug.Printf("failed to marshal node info request: %v\n", err)
		return
	}

	// Send our information to the controller
	_, err = io.WriteString(conn, string(jnodeInfo)+"\n")
	if err != nil {
		Ldebug.Printf("failed to send the node info to the controller: %v", err)
		return
	}

	// Prepare the keep alive ticker
	keepAlive := &keepAlive{
		Action: "keepalive",
	}

	jkeepAlive, err := json.Marshal(keepAlive)
	if err != nil {
		Ldebug.Printf("failed to marshal the keep alive: %v\n", err)
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
			// ticker detected a disconnect from the controller
			return
		default:
		}

		err = json.NewDecoder(conn).Decode(&switchInfo)
		if err != nil {
			Ldebug.Printf("failed to unmarshal the switch info: %v\n", err)
			return
		}

		if switchInfo.Action == "netinfos" &&
			(gSwitch.info.Addr != switchInfo.Addr ||
				gSwitch.info.Port != switchInfo.Port ||
				gSwitch.info.IPaddr != switchInfo.IPaddr ||
				gSwitch.info.Netmask != switchInfo.Netmask) {

			Ldebug.Printf("Addr: %s -- %s\n", gSwitch.info.Addr, switchInfo.Addr)
			Ldebug.Printf("Port: %s -- %s\n", gSwitch.info.Port, switchInfo.Port)
			Ldebug.Printf("IPaddr: %s -- %s\n", gSwitch.info.IPaddr, switchInfo.IPaddr)
			Ldebug.Printf("Netmask: %s -- %s\n", gSwitch.info.Netmask, switchInfo.Netmask)

			gSwitch.info.Addr = switchInfo.Addr
			gSwitch.info.Port = switchInfo.Port
			gSwitch.info.IPaddr = switchInfo.IPaddr
			gSwitch.info.Netmask = switchInfo.Netmask

			// FIXME
			// replace this section once these functions are included in the tuntap library
			cmd := exec.Command("ifconfig", utunName, gSwitch.info.IPaddr, gSwitch.info.IPaddr, "netmask", gSwitch.info.Netmask)
			Ldebug.Printf("%s\n", cmd.String())
			stderr, err := cmd.StderrPipe()
			if err != nil {
				Lerror.Fatalf("failed to initialize ifconfig command: %v", err)
			}
			err = cmd.Start()
			if err != nil {
				Lerror.Fatalf("failed to apply ifconfig on %v: %v\n", utunName, err)
			}
			slurp, _ := ioutil.ReadAll(stderr)
			if err := cmd.Wait(); err != nil {
				Ldebug.Printf("stderr: %v\n", slurp)
				Ldebug.Fatalf("failed to apply ifconfig on %v: %v\n", utunName, err)
			}

			// We want to extract the subnet from the IP and netmask
			// 192.168.0.1 & 255.255.0.0 --> 192.168.0.0
			ipv4addr := net.ParseIP(gSwitch.info.IPaddr)
			ipv4netmask := (net.ParseIP(gSwitch.info.Netmask)).To4()
			mask := net.IPv4Mask(ipv4netmask[0], ipv4netmask[1], ipv4netmask[2], ipv4netmask[3])
			subnet := ipv4addr.Mask(net.CIDRMask(mask.Size()))

			cmd = exec.Command("route", "add", "-net", subnet.String(), gSwitch.info.IPaddr, gSwitch.info.Netmask)
			Ldebug.Printf("%v\n", cmd.String())
			stderr, err = cmd.StderrPipe()
			if err != nil {
				Lerror.Fatalf("failed to initialize error pipe: %v", err)
			}
			err = cmd.Start()
			if err != nil {
				Lerror.Fatalf("failed to add new route on %v: %v", utunName, err)
			}
			slurp, _ = ioutil.ReadAll(stderr)
			if err := cmd.Wait(); err != nil {
				Ldebug.Printf("stderr: %v\n", slurp)
				Ldebug.Fatalf("failed to add new route on %v: %v\n", utunName, err)
			}

			// If switch is potentially running let's cancel it
			if gSwitch.cancel != nil {
				Ldebug.Printf("close the connection to the vswitch\n")
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
			Ldebug.Printf("start the connection to the vswitch\n")
			go connSwitch(gSwitch.ctx, gSwitch.cancel, config)
		}

		// Clear the content
		// FIXME use a generic var to switch on the 'action' field
		switchInfo = switchInformation{}
		time.Sleep(1 * time.Second)
	}
}

func ConnectNetwork(networkName string) {

	var certNetInfo certNetInformation
	var networkCred NetworkCredentials
	var arrayCtrlInfo arrayControllerInfo
	var netConf Ndb
	var i int

	// Read the configuration file
	byteValue, err := ioutil.ReadFile(GetNdbPath())
	if err != nil {
		Lerror.Fatalf("failed to read the configuration file: %v\n", err)
	}

	err = json.Unmarshal(byteValue, &netConf)
	if err != nil {
		Lerror.Fatalf("failed to unmarshal the network configuration: %v\n", err)
	}

	// Find the network in the list
	for i = 0; i < len(netConf.Networks); i++ {
		networkCred = netConf.Networks[i]
		if networkCred.Name == networkName {
			break
		}
	}

	if i >= len(netConf.Networks) {
		Lerror.Fatalf("failed to find the selected network: %v\n", networkName)
	}

	Ldebug.Printf("Name: %s\n", networkCred.Name)
	Ldebug.Printf("Cert: %s\n", networkCred.Cert)
	Ldebug.Printf("CAcert: %s\n", networkCred.CAcert)
	Ldebug.Printf("PVkey: %s\n", networkCred.PVkey)

	// Parse the Certificate and Private key to form the tls Certificate
	tlsCert, err := tls.X509KeyPair([]byte(networkCred.Cert), []byte(networkCred.PVkey))
	if err != nil {
		Lerror.Fatalf("unable to parse certs: %v", err)
	}

	// Parse the certificate PEM to create an x509 certificate object
	// that will allow us to extract the Subject field
	block, _ := pem.Decode([]byte(networkCred.Cert))
	if block == nil {
		Lerror.Fatal("failed to parse the certificate in PEM format")
	}
	x509cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		Lerror.Fatalf("failed to convert the certificate to x509 format: %v\n", err)
	}

	Ldebug.Printf("Certificate Subject: %v\n", x509cert.Subject)

	// Parse the network information from the Subject
	values, err := url.ParseQuery(strings.TrimLeft(x509cert.Subject.String(), "CN="))
	if err != nil {
		Lerror.Fatalf("failed to parse the network information from the certificate subject: %v\n", err)
	}

	certNetInfo.Version = values.Get("v")
	certNetInfo.Type = values.Get("t")
	certNetInfo.NetworkUID = values.Get("w")
	certNetInfo.NodeUID = values.Get("n")

	if certNetInfo.Version == "" {
		Lerror.Fatal("failed to find the version from the certificate subject")
	}
	if certNetInfo.Type == "" {
		Lerror.Fatal("failed to find the type from the certificate subject")
	}
	if certNetInfo.NetworkUID == "" {
		Lerror.Fatal("failed to find the network UID from the certificate subject")
	}
	if certNetInfo.NodeUID == "" {
		Lerror.Fatal("failed to find the node UID from the certificate subject")
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
		Lerror.Fatalf("failed to marshal the network info request: %v\n", err)
	}

	Ldebug.Printf("network info request: %s\n", jnetinfosReq)

	// Setup the http request that will carry our json request
	timeout := time.Duration(5 * time.Second)
	client := http.Client{
		Timeout: timeout,
	}

	request, err := http.NewRequest("POST", "https://"+networkCred.APIsrv+"/v1/netinfos", bytes.NewBuffer(jnetinfosReq))
	if err != nil {
		Lerror.Printf("failed to create a new https request: %v\n", err)
		return
	}
	request.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(request)
	if err != nil {
		Lerror.Printf("failed network info request: %v\n", err)
		return
	}
	defer resp.Body.Close()

	// Read the response to our request
	buf, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		Lerror.Printf("failed to parse network info response: %v\n", err)
		return
	}

	Ldebug.Printf("netinfos: %v\n", string(buf))

	err = json.Unmarshal(buf, &arrayCtrlInfo)
	if err != nil {
		Lerror.Fatalf("failed to unmarshal the controller information: %v\n", err)
	}

	if len(arrayCtrlInfo.NetInfos) <= 0 {
		Lerror.Fatalf("failed to receive the controller information\n")
	}

	Ldebug.Printf("result: %v\n", arrayCtrlInfo)

	Ldebug.Printf("ctrlInfo.Family: %s\n", arrayCtrlInfo.NetInfos[0].Family)
	Ldebug.Printf("ctrlInfo.Addr: %s\n", arrayCtrlInfo.NetInfos[0].Addr)
	Ldebug.Printf("ctrlInfo.Port: %s\n", arrayCtrlInfo.NetInfos[0].Port)
	Ldebug.Printf("ctrlInfo.Region: %s\n", arrayCtrlInfo.NetInfos[0].Region)

	ctx, cancel := context.WithCancel(context.Background())
	connController(ctx, cancel, &arrayCtrlInfo.NetInfos[0], &config)
}

func InitNetwork() {

	// Setup ARP structs.
	arpQueue = NewARPQueue(arpQueueMax)
	arpTable = &ArpTable{}

	gMAC = genMAC()

	config := water.Config{
		DeviceType: water.TUN,
	}
	config.Name = utunName

	var err error
	utun, err = water.New(config)
	if err != nil {
		Lerror.Fatalf("failed to initialize the %s interface: %v\n", utunName, err)
	}
}
