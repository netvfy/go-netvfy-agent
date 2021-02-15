package main

import (
	"os/exec"

	"github.com/getlantern/systray"
)

func main() {
	systray.Run(onReady, nil)
}

func onReady() {

	systray.SetTemplateIcon(icondata, icondata)

	mDisconnect := systray.AddMenuItem("Disconnect", "")
	mDisconnect.Disable()

	subMenuConnectNetwork := systray.AddMenuItem("Connect to network", "")
	subMenuConnectNetwork.AddSubMenuItem("my network", "")
	subMenuConnectNetwork.AddSubMenuItem("my other network", "")

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
	mQuitOrig := systray.AddMenuItem("Quit", "")

	for {
		select {
		case <-mDisconnect.ClickedCh:
		case <-mURL.ClickedCh:
			exec.Command("open", "https://netvfy.com").Start()
		case <-mQuitOrig.ClickedCh:
			systray.Quit()
			return
		}
	}
}
