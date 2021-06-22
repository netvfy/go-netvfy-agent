package main

import (
	"flag"
	"io"
	"io/ioutil"
	"log"
	"os"
	"time"

	agent "github.com/netvfy/go-netvfy-agent"
)

func listNetworks() {

	var i int

	ndb, err := agent.FetchNetworks(agent.GetNdbPath())
	if err != nil {
		agent.Lerror.Fatalf("listNetworks: %s\n", err)
	}

	agent.Linfo.Printf("Provisioned Networks:\n")
	// Find the network in the list
	for i = 0; i < len(ndb.Networks); i++ {
		agent.Linfo.Printf("\t%s\n", ndb.Networks[i].Name)
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
	if *verbose {
		dlogOut = os.Stdout
	}

	agent.Ldebug = log.New(dlogOut, "debug: ", log.Ldate|log.Ltime|log.Lshortfile)
	agent.Linfo = log.New(os.Stdout, "", 0)
	agent.Lerror = log.New(os.Stdout, "error: ", log.Ldate|log.Ltime|log.Lshortfile)

	if *provLink != "" {
		err := agent.ProvisionNetwork(*provLink, *netLabel)
		if err != nil {
			agent.Lerror.Fatal(err)
		}
		return
	} else if *list {
		listNetworks()
	} else if *connect != "" {

		agent.InitNetwork()
		go agent.ReadUTUN()

		for {
			agent.ConnectNetwork(*connect)
			time.Sleep(3 * time.Second)
		}
	} else if *delete != "" {
		agent.DeleteNetwork(*delete)
	} else {
		flag.PrintDefaults()
	}
}
