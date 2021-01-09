package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	water "github.com/netvfy/tuntap"
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
type safeIface struct {
	// TODO(sneha): thoughts on struct embedding here
	sync.Mutex
	*water.Interface
}

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
	safeIface := safeIface{sync.Mutex{}, ifce}

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

	readBuffLength := 100
	writeBuffLen := 100
	readChan := make(chan []byte, readBuffLength)
	writeChan := make(chan []byte, writeBuffLen)

	log.Println("starting the tun/tap listener...")
	log.Printf("Note traffic must be sourced from IP of iface like so: ping -S %v %v\n", addr, exampleDst)

	// goroutine 1 - read from tap interface
	go func() {
		fmt.Println("reading from tap...")
		for {
			fmt.Println("attempting read...")
			buff := make([]byte, 1500)
			safeIface.Lock()
			_, err := safeIface.Read(buff)
			if err != nil {
				log.Fatal(err)
			}
			safeIface.Unlock()
			readChan <- buff
		}
	}()

	go func() {
		fmt.Println("reading from switch...")
		// TODO(sneha): reading from tcp connection
		// For now this is a simple sleep plus default send for testing
		for {
			fmt.Println("attempting write...")
			writeChan <- []byte{}
			time.Sleep(5 * time.Second)
		}
	}()

	for {
		select {
		// TODO(add case to handle context cancellations, keyboard interrupts, SIGTERM)
		case writemsg := <-writeChan:
			fmt.Println("we've received from writeChan...")
			safeIface.Lock()
			_, err := safeIface.Write(writemsg)
			if err != nil {
				log.Printf("error writing to tap interface: %v", err)
			}
			safeIface.Unlock()
		case readmsg := <-readChan:
			fmt.Println("we've received from readChan...")
			// read from the connection
			// TODO: writes to tcp socket conn
			fmt.Println(readmsg)
		}

	}
}
