package main

import (
	"os/exec"

	agent "github.com/netvfy/go-netvfy-agent"

	"github.com/getlantern/systray"
)

func listNetworks(subMenuConnectNetwork *systray.MenuItem) {

	var i int

	path := agent.GetNdbPath()
	ndb, _ := agent.FetchNetworks(path)

	for i = 0; i < len(ndb.Networks); i++ {
		subMenuConnectNetwork.AddSubMenuItem(ndb.Networks[i].Name, "")
	}
}

func onReady() {

	systray.SetTemplateIcon(icondata, icondata)

	mDisconnect := systray.AddMenuItem("Disconnect", "")
	mDisconnect.Disable()

	subMenuConnectNetwork := systray.AddMenuItem("Connect to network", "")
	listNetworks(subMenuConnectNetwork)

	systray.AddSeparator()

	systray.AddMenuItem("Add a new network", "")

	subMenuDeleteNetwork := systray.AddMenuItem("Delete a network", "")
	subMenuDeleteNetwork.AddSubMenuItem("my network", "")
	subMenuDeleteNetwork.AddSubMenuItem("my other network", "")

	systray.AddSeparator()

	systray.AddMenuItem("Show logs", "")
	mURL := systray.AddMenuItem("netvfy.com", "")
	mVersion := systray.AddMenuItem("version gc0.1-g1", "")
	mVersion.Disable()

	systray.AddSeparator()
	mQuit := systray.AddMenuItem("Quit", "")

	for {
		select {
		case <-mDisconnect.ClickedCh:
		case <-mURL.ClickedCh:
			exec.Command("open", "https://netvfy.com").Start()
		case <-mQuit.ClickedCh:
			systray.Quit()
			return
		}
	}
}

func main() {
	systray.Run(onReady, nil)
}
