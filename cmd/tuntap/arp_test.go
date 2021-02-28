package main

import (
	"net"
	"reflect"
	"testing"
)

// TestArpTable tests creation of arptable, addition, and removal of values.
func TestArpTable(t *testing.T) {
	arpTable := &ArpTable{}

	// generate test values
	// ArpEntry 1
	testIP := "127.0.0.1"
	testMAC := "ac:de:48:00:11:22"

	testMACHW, err := net.ParseMAC(testMAC)
	if err != nil {
		t.Fatalf("unable to parse MAC1: %v", err)
	}

	testARPEntry := &ArpEntry{
		IP:     net.ParseIP(testIP),
		Mac:    testMACHW,
		Status: StatusReady,
	}

	// ArpEntry 2
	testIP2 := "127.0.0.2"
	testMAC2 := "1e:77:9d:c0:09:c4"

	testMACHW2, err := net.ParseMAC(testMAC2)
	if err != nil {
		t.Fatalf("unable to parse MAC2, %v", err)
	}

	testARPEntry2 := &ArpEntry{
		IP:     net.ParseIP(testIP2),
		Mac:    testMACHW2,
		Status: StatusReady,
	}

	// Add ArpEntry 1
	err = arpTable.Add(testIP)
	if err != nil {
		t.Fatalf("unable to add testIP1: %v", err)
	}

	// Update ArpEntry 1 and and check it exists
	err = arpTable.Update(testIP, testMACHW)
	if err != nil {
		t.Fatalf("unable to add testIP2: %v", err)
	}

	entryResult, ok, err := arpTable.Get(testIP)
	if err != nil {
		t.Fatalf("unable to retrieve testIP1: %v", err)
	}
	if !ok {
		t.Fatalf("unable to retrieve testIP1: %v", err)
	}

	if !compareArpEntry(entryResult, testARPEntry) {
		t.Fatalf("actual arp entry is not equal to expected ARP Entry")
	}

	// Update Arp Entry 2 and check 1 and 2 exist
	err = arpTable.Add(testIP2)
	if err != nil {
		t.Fatalf("unable to retrieve testIP2")
	}

	// Delete Arp Entry 1 and ensure that it was removed
	err = arpTable.Update(testIP2, testMACHW2)
	if err != nil {
		t.Fatalf("unable to update arp entry for testIP2: %v", err)
	}

	// Ensure both ArpEntry1 and ArpEntry2 are in the table
	entryResult, ok, err = arpTable.Get(testIP)
	if err != nil {
		t.Fatalf("unable to retrieve testIP1: %v", err)
	}
	if !ok {
		t.Fatalf("unable to retrieve testIP1: %v", err)
	}

	if !compareArpEntry(entryResult, testARPEntry) {
		t.Fatalf("actual arp entry is not equal to expected ARP Entry")
	}

	entryResult, ok, err = arpTable.Get(testIP2)
	if err != nil {
		t.Fatalf("unable to retrieve testIP1: %v", err)
	}
	if !ok {
		t.Fatalf("unable to retrieve testIP1: %v", err)
	}

	if !compareArpEntry(entryResult, testARPEntry2) {
		t.Fatalf("actual arp entry is not equal to expected ARP Entry")
	}

	// Remove ArpEntry 1 and ensure it's gone.
	err = arpTable.Remove(testIP)
	if err != nil {
		t.Fatalf("unable to remove testIP1: %v", err)
	}

	_, ok, err = arpTable.Get(testIP)
	if err != nil {
		t.Fatalf("unable to retrieve testIP1: %v", err)
	}
	if ok {
		t.Fatalf("ArpEntry 1 unexpectedly not removed")
	}

	// Remove ArpEntry 2 and ensure it's gone.
	err = arpTable.Remove(testIP2)
	if err != nil {
		t.Fatalf("unable to remove testIP2: %v", err)
	}

	_, ok, err = arpTable.Get(testIP2)
	if err != nil {
		t.Fatalf("unable to retrieve testIP2: %v", err)
	}

	if ok {
		t.Fatalf("ArpEntry2 unexpectedly not removed")
	}

}

func compareArpEntry(e1 *ArpEntry, e2 *ArpEntry) bool {
	// TODO: use go-cmp instead of deepequal
	if !reflect.DeepEqual(e1.IP, e2.IP) {
		return false
	}
	if !reflect.DeepEqual(e1.Mac.String(), e2.Mac.String()) {
		return false
	}

	if !reflect.DeepEqual(e1.Status, e2.Status) {
		return false
	}

	return true
}

// TestArpQueue tests the basic Add, Len, SendAndRemove functionality of ArpQueue.
func TestArpQueue_Add(t *testing.T) {
	testBuff := []byte("test")

	queue, err := NewARPQueue(2)
	if err != nil {
		t.Fatalf("unable to create NewARPQueue: %v", err)
	}

	queue.Add(testBuff)

	if queue.Len() != 1 {
		t.Fatal("unexpected queue length")
	}
}

// TestArpQueue tests the basic SendAndRemove functionality of ArpQueue.
// TODO - FIX THIS TEST to essential test the iteration components
func TestArpQueue_Iterate(t *testing.T) {
	// generate test frame
	buff, err := generateTestFrame()
	if err != nil {
		t.Fatalf("unable to generate test frame: %v", buff)
	}

	// create ArpQueue and add
	queue, err := NewARPQueue(2)
	if err != nil {
		t.Fatalf("unable to create queue: %v", err)
	}

	queue.Add(buff)
	queue.Add(buff)

	len := queue.Len()
	if len != 2 {
		t.Fatalf("unexpected buffer length: %v", len)
	}

	sentMessages := make(chan []byte, 10)
	fn := func(buff []byte) error {
		sentMessages <- buff
		return nil
	}

	queue.IterateAndRun(net.ParseIP(testIP), fn)

	count := 0
	for elem := range sentMessages {
		if !reflect.DeepEqual(elem, buff) {
			t.Fatalf("unexpected received buffer: %v", elem)
		}
		if count == 2 {
			break
		}
		count++
	}

	len = queue.Len()
	if len != 0 {
		t.Fatalf("unexpected queue length: %v", len)
	}
}
