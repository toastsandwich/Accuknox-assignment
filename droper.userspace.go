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

type Data_t struct {
	Protocol uint32
	Port     uint32
	Status   [5]byte
	Padding  [3]byte
}

func main() {
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal("removing mem lock: ", err)
	}

	var obj droperObjects
	if err := loadDroperObjects(&obj, nil); err != nil {
		log.Fatal("loading object: ", err)
	}
	defer obj.Close()

	ifname := "ens33"
	iface, err := net.InterfaceByName(ifname)
	if err != nil {
		log.Fatal("getting interface: ", err)
	}

	link, err := link.AttachXDP(link.XDPOptions{
		Program:   obj.DropTcpPackets,
		Interface: iface.Index,
	})
	if err != nil {
		log.Fatal("linking XDP: ", err)
	}
	defer link.Close()

	log.Println("looking for TCP packet(s)")

	tick := time.Tick(time.Second)
	stop := make(chan os.Signal, 5)
	signal.Notify(stop, os.Interrupt)

	for {
		select {
		case <-tick:
			var key uint32 = 0
			var value Data_t
			var proto string
			err := obj.TcpPktT.Lookup(&key, &value)
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
