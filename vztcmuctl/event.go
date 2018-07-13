package main

import (
	"fmt"
	lv "github.com/libvirt/libvirt-go"
)

var terminated = false

func init() {
	lv.EventRegisterDefaultImpl()
}

func eventCallBack(c *lv.Connect, d *lv.Domain, event *lv.DomainEventLifecycle) {
	fmt.Printf("EVENT %s", event.Event)
}

func isTerminated() (bool) {
	return terminated
}

func startEvent(con *lv.Connect, dom *lv.Domain, c chan int ) {
	callbackId, err := con.DomainEventLifecycleRegister(dom, eventCallBack)
	if err != nil {
		panic(err)
	}

	for !isTerminated() {
		lv.EventRunDefaultImpl()
		fmt.Printf("X\n")
	}

	con.DomainEventDeregister(callbackId)
	c <- 1
}

func stopEvent(c chan int) {
	fmt.Printf("event Wait...\n")
	terminated = true
	<-c
	fmt.Printf("event Done\n")
}
