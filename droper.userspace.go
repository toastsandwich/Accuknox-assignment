package main

import (
	"log"
	"net"
	"os"
	"os/signal"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

/*
struct similar to data_t in droper.bpf.c,
padding to added to make status a multiple of 8 in both codes
*/
type Data_t struct {
	Protocol uint32
	Port     uint32
	Status   [5]byte
	Padding  [3]byte
}

func main() {
	// Removes MemLock required for kernels with version 5.1 or lesser it is required
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal("removing mem lock: ", err)
	}

	// Load the comiled eBPF ELF and load it to kernel
	var obj droperObjects
	if err := loadDroperObjects(&obj, nil); err != nil {
		log.Fatal("loading object: ", err)
	}
	defer obj.Close()

	ifname := "ens33" // <- used virtual machine | else use 'eth0 or wlan0'
	iface, err := net.InterfaceByName(ifname)
	if err != nil {
		log.Fatal("getting interface: ", err)
	}
	//  Attached DropTcpPackets to network interface
	link, err := link.AttachXDP(link.XDPOptions{
		Program:   obj.DropTcpPackets,
		Interface: iface.Index,
	})
	if err != nil {
		log.Fatal("linking XDP: ", err)
	}
	defer link.Close()

	log.Println("looking for TCP packet(s)")

	// Periodically fetch the Data_t from TcpPktT, exit when iterupted
	tick := time.Tick(time.Second)
	stop := make(chan os.Signal, 5)
	signal.Notify(stop, os.Interrupt)

	for {
		select {
		case <-tick:
			var key uint32 = 0
			var value Data_t
			var proto string
			err := obj.TcpPktT.Lookup(&key, &value) //get elem from key
			if err != nil {
				log.Println("map lookup: ", err)
				continue
			}

			if value.Protocol == 6 {
				proto = "TCP"
			} else {
				proto = "Other than TCP"
			}

			if value.Port == 4040 {
				log.Printf("TCP packet caught: Protocol=%s, Port=%d, Status=%s\n", proto, value.Port, string(value.Status[:]))
			} else {
				log.Printf("TCP packet passed: Protocol=%s, Port=%d, Status=%s\n", proto, value.Port, string(value.Status[:]))
			}
		case <-stop:
			log.Println("recieved stop signal, exiting...")
			return
		}
	}
}
