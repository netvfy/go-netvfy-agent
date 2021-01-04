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
	"time"

	water "github.com/netvfy/tuntap"
)

// IPConfig contains routing and interface configuration information
type IPConfig struct {
	Netmask string
	Addr    string
	Subnet  string
}

// configureInterface execs two commands
func configureInterface(osName, iface string, ipConfig *IPConfig) error {
	// TODO(sneha): consider how to do this for other operating systems
	// var routeCmd *exec.Cmd
	// var ipCmd *exec.Cmd
	// switch osName {
	// default:
	// }

	// STEP 2: Configure tun interface address
	cmd2 := exec.Command("sudo", "ifconfig", "utun9", ipConfig.Addr, ipConfig.Addr, "netmask", ipConfig.Netmask)
	stderr, err := cmd2.StderrPipe()

	log.Printf("Running ifconfig command and waiting for it to finish...")
	err = cmd2.Start()
	if err != nil {
		log.Fatalf("Command failed to start with error: %v", err)
	}

	slurp, _ := ioutil.ReadAll(stderr)
	fmt.Printf("%s\n", slurp)

	if err := cmd2.Wait(); err != nil {
		log.Fatal(err)
	}
	log.Println("Command ifconfig successfully run...")

	time.Sleep(2)

	// TODO(sneha): create command wrapper struct/funcs
	// STEP 1: Add Route
	cmd := exec.Command("sudo", "route", "add", "-net", ipConfig.Subnet, ipConfig.Addr, "-ifscope", iface)
	stderr, err = cmd.StderrPipe()

	log.Printf("Running add route command and waiting for it to finish...")
	err = cmd.Start()
	if err != nil {
		log.Fatalf("Command failed to start with error: %v", err)
	}

	slurp, _ = ioutil.ReadAll(stderr)
	fmt.Printf("%s\n", slurp)

	if err := cmd.Wait(); err != nil {
		log.Fatal(err)
	}
	log.Println("Command add route successfully run...")

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

	for {
		log.Println("starting the tun/tap listener...")
		log.Printf("Note traffic must be sourced from IP of iface like so: ping -S %v %v", addr, exampleDst)
		buff := make([]byte, 1500)
		// read from the connection
		n, err := ifce.Read(buff)
		// TODO(sneha): switch statement to account for different errors
		if err != nil {
			log.Println("tun/tap listened stopped ")
			log.Fatal(err)
		}

		fmt.Println(n)
		fmt.Printf("%v", buff)
	}
}
