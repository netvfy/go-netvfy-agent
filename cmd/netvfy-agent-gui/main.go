package main

import (
	"os/exec"
	"runtime"

	agent "github.com/netvfy/go-netvfy-agent"

	"github.com/progrium/macdriver/cocoa"
	"github.com/progrium/macdriver/core"
	"github.com/progrium/macdriver/objc"
)

func listNetworks(message *chan string, menuConnectNetwork *cocoa.NSMenu, menuDeleteNetwork *cocoa.NSMenu) {
	var i int

	path := agent.GetNdbPath()
	ndb, _ := agent.FetchNetworks(path)

	for i = 0; i < len(ndb.Networks); i++ {

		item := cocoa.NSMenuItem_New()
		item.SetTitle(ndb.Networks[i].Name)
		item.SetEnabled(true)
		item.SetAction(objc.Sel("add," + ndb.Networks[i].Name + ":"))
		cocoa.DefaultDelegateClass.AddMethod("add,"+ndb.Networks[i].Name+":", func(o objc.Object) {
			// TODO connect to selected network
		})
		menuConnectNetwork.AddItem(item)

		item2 := cocoa.NSMenuItem_New()
		item2.SetTitle(ndb.Networks[i].Name)
		item2.SetEnabled(true)
		item2.SetAction(objc.Sel("del," + ndb.Networks[i].Name + ":"))
		cocoa.DefaultDelegateClass.AddMethod("del,"+ndb.Networks[i].Name+":", func(o objc.Object) {
			// TODO pop-up to confirm
			// TODO agent.DeleteNetwork(agent.GetNdbPath(), item2.Title())
			menuDeleteNetwork.RemoveItem(item2)
			item2.Release()
			menuConnectNetwork.RemoveItem(item)
			item.Release()
		})
		menuDeleteNetwork.AddItem(item2)
	}
}

func main() {
	runtime.LockOSThread()

	messages := make(chan string)

	app := cocoa.NSApp_WithDidLaunch(func(n objc.Object) {

		obj := cocoa.NSStatusBar_System().StatusItemWithLength(cocoa.NSVariableStatusItemLength)
		obj.Retain()

		data := core.NSData_WithBytes(icondata, uint64(len(icondata)))
		image := cocoa.NSImage_InitWithData(data)
		image.SetSize(core.NSSize{Width: 16, Height: 16})
		obj.Button().SetImage(image)

		menu := cocoa.NSMenu_New()
		menu.SetAutoenablesItems(false)

		// Disconnect
		itemDisconnect := cocoa.NSMenuItem_New()
		itemDisconnect.SetTitle("Disconnect")
		itemDisconnect.SetEnabled(false)
		menu.AddItem(itemDisconnect)

		// Connect menu
		itemConnect := cocoa.NSMenuItem_New()
		itemConnect.SetTitle("Connect to network")
		menu.AddItem(itemConnect)

		itemConnectMenu := cocoa.NSMenu_New()
		itemConnectMenu.SetAutoenablesItems(false)
		itemConnect.SetSubmenu(itemConnectMenu)

		menu.AddItem(cocoa.NSMenuItem_Separator())

		// Add Network
		itemAddNetwork := cocoa.NSMenuItem_New()
		itemAddNetwork.SetTitle("Add a new network")
		itemAddNetwork.SetEnabled(true)
		menu.AddItem(itemAddNetwork)

		// Delete menu
		itemDelete := cocoa.NSMenuItem_New()
		itemDelete.SetTitle("Delete a network")
		menu.AddItem(itemDelete)
		itemDeleteMenu := cocoa.NSMenu_New()
		itemDeleteMenu.SetAutoenablesItems(false)
		itemDelete.SetSubmenu(itemDeleteMenu)

		menu.AddItem(cocoa.NSMenuItem_Separator())

		itemShowLogs := cocoa.NSMenuItem_New()
		itemShowLogs.SetTitle("Show Logs")
		itemShowLogs.SetAction(objc.Sel("showLogs:"))
		cocoa.DefaultDelegateClass.AddMethod("showLogs:", func(_ objc.Object) {
			// TODO open logs
		})
		menu.AddItem(itemShowLogs)

		itemHomePage := cocoa.NSMenuItem_New()
		itemHomePage.SetTitle("netvfy.com")
		itemHomePage.SetAction(objc.Sel("homePage:"))
		cocoa.DefaultDelegateClass.AddMethod("homePage:", func(_ objc.Object) {
			exec.Command("open", "https://netvfy.com").Start()
		})
		menu.AddItem(itemHomePage)

		itemVersion := cocoa.NSMenuItem_New()
		itemVersion.SetTitle("version gc0.1-g1")
		itemVersion.SetEnabled(false)
		menu.AddItem(itemVersion)

		menu.AddItem(cocoa.NSMenuItem_Separator())

		itemQuit := cocoa.NSMenuItem_New()
		itemQuit.SetTitle("Quit")
		itemQuit.SetAction(objc.Sel("terminate:"))
		menu.AddItem(itemQuit)

		/*
			itemA1 := cocoa.NSMenuItem_New()
			itemA1.SetTitle("A1")
			menu.Send("insertItem:atIndex:", itemA1, 1)
		*/

		listNetworks(&messages, &itemConnectMenu, &itemDeleteMenu)

		obj.SetMenu(menu)
	})
	app.Run()
}
