package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"time"

	water "github.com/netvfy/tuntap"
	ipv4 "golang.org/x/net/ipv4"
)

// IPConfig contains routing and interface configuration information
type IPConfig struct {
	Netmask string
	Addr    string
	Subnet  string
}

// generic wrapper to run command
func runCmd(name string, cmd *exec.Cmd) error {
	log.Printf("Configuring error pipe for: %v\n", name)
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return fmt.Errorf("%v unable to configure error pipe: %v", name, err)
	}

	log.Printf("starting command: %v\n", name)
	err = cmd.Start()
	if err != nil {
		return fmt.Errorf("%v command failed to start with error: %v", name, err)
	}
	slurp, _ := ioutil.ReadAll(stderr)
	fmt.Printf("%s\n", slurp)

	if err := cmd.Wait(); err != nil {
		return fmt.Errorf("%v command failed to complete with error: %v", name, err)
	}

	log.Printf("command finished successfully: %v\n", name)
	return nil
}

// configureInterface execs two commands
func configureInterface(osName, iface string, ipConfig *IPConfig) error {
	// TODO(sneha): consider how to do this for other operating systems
	var routeCmd *exec.Cmd
	var ipCmd *exec.Cmd
	switch osName {
	case "darwin":
		routeCmd = exec.Command("sudo", "ifconfig", "utun9", ipConfig.Addr, ipConfig.Addr, "netmask", ipConfig.Netmask)
		ipCmd = exec.Command("sudo", "route", "add", "-net", ipConfig.Subnet, ipConfig.Addr, "-ifscope", iface)
	default:
		return fmt.Errorf("the agent cannot run on this machine")
	}

	// Set interface address
	fmt.Printf("Configuring interface address for: %v\n", iface)
	err := runCmd("set address", routeCmd)
	if err != nil {
		log.Printf("failed to set address: %v\n", err)
		return fmt.Errorf("unable to set address")
	}

	time.Sleep(2)

	// Add route for vpn subnet
	fmt.Println("Configuring routes")
	err = runCmd("add routes", ipCmd)
	if err != nil {
		log.Printf("failed to add route: %v\n", err)
		return fmt.Errorf("unable to add route")
	}

	return nil
}

// validateInterfaceMacOs ensures that the interface should be of the format utun<Num>
func validateInterface(osName, iface string) bool {
	switch osName {
	// OSX expects interface names utun
	case "darwin":
		if !strings.Contains(iface, "utun") {
			return false
		}

		res := strings.Split(iface, "utun")
		if len(res) != 2 {
			return false
		}

		num, err := strconv.ParseInt(res[1], 10, 64)
		if err != nil {
			return false
		}

		if num < 0 {
			return false
		}
	case "linux":
		if !strings.Contains(iface, "tun") {
			return false
		}

		res := strings.Split(iface, "tun")
		if len(res) != 2 {
			return false
		}

		num, err := strconv.ParseInt(res[1], 10, 64)
		if err != nil {
			return false
		}

		if num < 0 {
			return false
		}
	default:
		return false
	}

	return true
}

// TODO(sneha): is this necessary or is the interface type threadsafe?
// Probably not - device driver has separate read/write queues. so this shouldn't be a problem
// (can also do read/write syscall at the same time)
// type safeIface struct {
// 	// TODO(sneha): thoughts on struct embedding here
// 	sync.Mutex
// 	*water.Interface
// }

var interfaceFlag string

func main() {
	// Retrieve operating system name
	osName := runtime.GOOS

	flag.StringVar(&interfaceFlag, "interface", "utun9", "tun interface name for service")
	flag.Parse()

	// Validate name of interface
	if !validateInterface(osName, interfaceFlag) {
		log.Fatalf("invalid interface name: %v", interfaceFlag)
	}

	// TODO(sneha):  modify tuntap package to have a function that checks for the existence of the interface
	config := water.Config{
		DeviceType: water.TUN,
	}
	config.Name = interfaceFlag
	// Note: This is how the tun interface can be persisted
	//config.Persist = true
	// TODO(sneha): change permissions of the tun/tap interface to be in the same usergroup as this process

	ifce, err := water.New(config)
	if err != nil {
		log.Fatal(err)
	}

	// Add address to interface and routes
	subnet := "198.18.0.0/16"
	addr := "198.18.0.1"
	netmask := "255.255.0.0"
	exampleDst := "198.18.0.5"

	ipConfig := &IPConfig{
		Addr:    addr,
		Netmask: netmask,
		Subnet:  subnet,
	}

	err = configureInterface(osName, interfaceFlag, ipConfig)
	if err != nil {
		log.Fatalf("unable to configure agent: %v", err)
	}

	log.Println("starting the tun/tap listener...")
	log.Printf("Note traffic must be sourced from IP of iface like so: ping -S %v %v\n", addr, exampleDst)

	buffLen := 100
	waitBuffLen := 1000
	ingressBuffer := make(chan []byte, buffLen)
	egressBuffer := make(chan []byte, buffLen)
	egressWaitBuffer := make(chan []byte, waitBuffLen)
	done := make(chan int, 1)

	// TODO(sneha): can use waitgroup or actor model of multiple goroutines to make this far far cleaner,
	// handle SIGTERM, cleanup, context cancellation etc.

	//goroutine #1 - read from tun interface
	go func() {
		fmt.Println("reading from tap...")
		for {
			buff := make([]byte, 1518)
			_, err := ifce.Read(buff[14:])
			fmt.Println("incoming read...")
			if err != nil {
				log.Printf("unable to read from iface: %v", err)
				continue
			}
			egressBuffer <- buff
		}
	}()

	// goroutine #2 - write to tun interface
	go func() {
		fmt.Println("writing to tap...")
		for {
			buff := <-ingressBuffer
			fmt.Println("outgoing write...")
			_, err := ifce.Write(buff)
			if err != nil {
				log.Printf("there is an error writing: %v", err)
			}
		}
	}()

	// goroutine #3 - read from conn interface
	// TODO(sneha): need to make far cleaner but for now can test this way
	go func() {
		fmt.Println("reading from switch...")
		for {
			fmt.Println("incoming from tcpconn...")
			hdr := ipv4.Header{
				Version:  ipv4.Version,
				Len:      ipv4.HeaderLen + 4,
				TOS:      1,
				TotalLen: 0xbef3,
				ID:       0xcafe,
				Flags:    ipv4.DontFragment,
				FragOff:  1500,
				TTL:      255,
				Protocol: 1,
				Checksum: 0xdead,
				Src:      net.ParseIP("198.18.0.5"), Dst: net.ParseIP("198.18.0.1"),
			}
			buff, err := hdr.Marshal()
			if err != nil {
				fmt.Printf("unable to parse header: %v\n", err)
				continue
			}
			ingressBuffer <- buff
			time.Sleep(2 * time.Second)
		}
	}()

	//TODO: do we specify our switch only works for IPv4?

	// goroutine #4 - write to conn interface
	// TODO(sneha): need to write but for now will printout
	go func() {
		fmt.Println("writing to switch...")
		for {
			buff := <-egressBuffer
			// TODO(sneha): check ARP cache
			// If no ARP cache, send out ARP broadcast and wait for reply
			// Source: https://flylib.com/books/en/3.475.1.78/1/

			// Grab IP address from buffer
			// ethernet header - 14 bytes
			// dst IP starts 16 bytes into IP header
			rawIP := buff[30:34]
			var ipv4 net.IP
			ipv4 = rawIP
			fmt.Println(ipv4.String())

			// if mac not found in hashtable
			// add entry and push to arpChannel
			entry, ok := ArpTable.Load(ipv4.String())
			if !ok {
				ArpTable.Store(ipv4.String(), ArpEntry{Status: StatusReady, Timestamp: time.Now()})
				egressWaitBuffer <- buff
				continue
			}
			arpEntry := entry.(*ArpEntry)
			if arpEntry.Status != StatusReady {
				continue
			}

			// Frame is of this struct
			// Ethernet Header
			//  destination MAC - 6 bytes
			//  source MAC - 6 bytes
			//  ether type - 2 bytes
			// IP Header
			//  version + IHL - 1 byte
			//  DSCP + ECN - 1 byte
			//  Total IP packet length (plus header) - 2 bytes
			// Payload

			// Add ethernet header
			etherType := []byte("\x800")
			srcMAC := make([]byte, 6) // TODO(sneha): change from hardcoded 0 values

			// add ethernet header
			copy(buff[0:6], arpEntry.Mac)
			copy(buff[6:12], srcMAC)
			copy(buff[12:14], etherType)

			len := binary.BigEndian.Uint16(buff[16:18])

			fmt.Println("outgoing to tcpconn...")
			fmt.Println(buff[0 : 14+len])
		}
	}()

	go func() {
		// read from ARP channel and try arping while awaiting a response
		//buff := <-egressWaitBuffer

		// grab IP

		// craft ARP packet

		// send ARP and await response
		// - should this be blocking while awaiting ARP response?
		// - is spinning up a new gourtine here better or can this be done above?
	}()

	go func() {
		// check ARP table for stale entries - based on default timeout issue
	}()

	// block on main thread until something shuts down the program
	//TODO(sneha): listen for keyboard interrupt or SIGTERM/SIGKILL
	select {
	case <-done:
		fmt.Println("closing interface...")
		err := ifce.Close()
		if err != nil {
			fmt.Printf("error closing interface: %v", err)
		}
	}
}