package main

import (
	"net"
	"reflect"
	"testing"
	"time"
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
	length := 2

	testBytes1, err := generateTestFrame(srcIP, testIP1)
	if err != nil {
		t.Fatalf("unable to generate testIP frame: %v", err)
	}
	testBytes2, err := generateTestFrame(srcIP, testIP2)
	if err != nil {
		t.Fatalf("unable to generate testIP frame: %v", err)
	}
	testBytes3, err := generateTestFrame(srcIP, testIP3)
	if err != nil {
		t.Fatalf("unable to generate testIP frame: %v", err)
	}

	queue, err := NewARPQueue(length)
	if err != nil {
		t.Fatalf("unable to create NewARPQueue: %v", err)
	}

	queue.Add(testIP1, testBytes1)
	if queue.Len() != 1 {
		t.Fatal("unexpected queue length")
	}

	queue.Add(testIP2, testBytes2)
	queue.Add(testIP3, testBytes3)

	// Check that queue has not overflowed limit
	if queue.Len() != 2 {
		t.Fatalf("unexpected queue length: %v", queue.Len())
	}

	// Confirm that value testIP1 no longer exists in the queue
	found := false
	e := queue.Front()
	for e != nil {
		entry, ok := e.Value.(*ArpQueueEntry)
		if !ok {
			t.Fatalf("invalid items in ArpQueue for IP: %v", entry.IP)
		}
		if entry.IP == testIP1 {
			found = true
		}
		e = e.Next()
	}

	if found {
		t.Fatalf("last added item unexpected not removed from queue: %v", testIP1)
	}
}

// TestArpQueue tests the basic SendAndRemove functionality of ArpQueue.
func TestArpQueue_Iterate(t *testing.T) {
	// generate test frame
	buff, err := generateTestFrame(testIP1, srcIP)
	if err != nil {
		t.Fatalf("unable to generate test frame: %v", buff)
	}

	// create ArpQueue and add
	queue, err := NewARPQueue(2)
	if err != nil {
		t.Fatalf("unable to create queue: %v", err)
	}

	queue.Add(testIP1, buff)
	queue.Add(testIP1, buff)

	len := queue.Len()
	if len != 2 {
		t.Fatalf("unexpected buffer length: %v", len)
	}

	sentMessages := make(chan []byte, 10)
	fn := func(buff []byte) error {
		sentMessages <- buff
		return nil
	}

	queue.IterateAndRun(testIP1, fn)

	timer1 := time.NewTimer(5 * time.Second)

	count := 1
	for {
		select {
		case msg := <-sentMessages:
			if !reflect.DeepEqual(msg, buff) {
				t.Fatalf("unexpected received buffer: %v", msg)
			}
			if count == 2 {
				len = queue.Len()
				if len != 0 {
					t.Fatalf("unexpected queue length: %v", len)
				}
				return
			}
			count++
		case <-timer1.C:
			t.Fatal("test timed out without iterating through results")
		}
	}
}
