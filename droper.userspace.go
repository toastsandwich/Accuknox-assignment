package main

import (
	"log"

	"github.com/cilium/ebpf/rlimit"
)

func main() {
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal("error removing mem lock: ", err)
	}
	
}
