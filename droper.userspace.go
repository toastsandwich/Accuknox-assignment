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

func main() {
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal("removing memlock: ", err)
	}

	var obj droperObjects
	if err := loadDroperObjects(&obj, nil); err != nil {
		log.Fatal("loading eBPF objects: ", err)
	}
	defer obj.Close()

	ifname := "ens33"
	iface, err := net.InterfaceByName(ifname)
	if err != nil {
		log.Fatal("getting interface: ", err)
	}

	link, err := link.AttachXDP(link.XDPOptions{
		Program:   obj.CountTcpPackets,
		Interface: iface.Index,
	})
	if err != nil {
		log.Fatal("attaching xdp: ", err)
	}
	defer link.Close()

	tick := time.Tick(time.Second)
	stop := make(chan os.Signal, 5)
	signal.Notify(stop, os.Interrupt)

	for {
		select {
		case <-tick:
			var count uint64
			err := obj.TcpPktCountT.Lookup(uint32(0), &count)
			if err != nil {
				log.Fatal("map lookup: ", err)
			}
			log.Println("recieved tcp packets", count)
		case <-stop:
			log.Println("recieved stop signal, exiting...")
			return
		}
	}
}
