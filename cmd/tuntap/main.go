package main

import (
	"fmt"
	"log"

	water "github.com/netvfy/tuntap"
)

func main() {
	// TODO(sneha):  modify tuntap package to have a function that checks for the existence of the interface
	config := water.Config{
		DeviceType: water.TUN,
	}
	config.Name = "utun9"
	// Note: This is how the tun interface can be persisted
	//config.Persist = true

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
	for {
		buff := make([]byte, 1500)
		// read from the connection
		n, err := ifce.Read(buff)
		// TODO(sneha): switch statement to account for different errors
		if err != nil {
			log.Fatal(err)
		}

		fmt.Println(n)
		fmt.Printf("%v", buff)
	}
}
