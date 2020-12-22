package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"os/exec"
	"time"

	water "github.com/netvfy/tuntap"
)

type IPConfig struct {
	IP      string
	NetMask string
	Gateway string
	Subnet  string
}

// TODO(sneha): function will run in here
func setupAddresses(iface string, ipConfig *IPConfig) error {
	return nil
}

func main() {
	// TODO(sneha):  modify tuntap package to have a function that checks for the existence of the interface
	config := water.Config{
		DeviceType: water.TUN,
	}
	config.Name = "utun9"
	// Note: This is how the tun interface can be persisted
	//config.Persist = true
	// TODO(sneha): change permissions of the tun/tap interface to be in the same usergroup as this process

	ifce, err := water.New(config)
	if err != nil {
		log.Fatal(err)
	}

	// TODO(sneha): Assign IP address to interface
	// Parametrize and make os.exec calls to this
	// For now - doing this manually->
	//        1. sudo ifconfig utun9 10.100.0.3 10.100.0.1 netmask 255.255.0.0
	//	     Explanation: src is IP and dst is the gateway, this is a /16 subnet
	//        2. sudo route add -net 10.100.0.0/16 10.100.0.1
	//	     Explanation: route add subnet to gateway
	//        3. ping 10.100.0.42
	// Despite the requirement of point-to-point, adding the above src, dst, and route
	// let's us still see the traffic
	// https://github.com/netvfy/tapcfg/blob/master/src/lib/tapcfg_unix_linux.h#L76
	subnet := "10.100.0.0/16"
	gateway := "10.100.0.1"
	netmask := "255.255.0.0"
	//addr := "10.100.0.3"

	// STEP 2: Configure tun interface address
	cmd2 := exec.Command("sudo", "ifconfig", "utun9", gateway, gateway, "netmask", netmask)
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
	cmd := exec.Command("sudo", "route", "add", "-net", subnet, gateway, "-ifscope", "utun9")
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

	for {
		log.Println("starting the tun/tap listener...")
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
