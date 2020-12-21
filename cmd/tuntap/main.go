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
	// For now - doing this manually->
	//        1. sudo ifconfig utun2 10.1.0.10 10.1.0.20 up
	//        2. ping 10.1.0.20
	// Can actually see packets being read.
	// However this is only a point-to-point tun interface.
	// Can we assign a specific unicast address, mask, and a gateway to a tun address?
	// Need to make a syscall like this ->
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
