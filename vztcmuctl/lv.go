package main

import (
	"fmt"
	lv "github.com/libvirt/libvirt-go"
)

func connect() (* lv.Connect){
	con, err := lv.NewConnect("qemu:///system")
	if err != nil {
		 panic(err)
	}
	return con
}

func startDom(con *lv.Connect) (* lv.Domain){
	xml := domanXml()
	dom, err := con.DomainCreateXML(xml, lv.DOMAIN_NONE)
	if err != nil {
		panic(err)
	}

	return dom
}

func stopDom(dom *lv.Domain) {
	err := dom.Destroy()
	if err != nil {
		panic(err)
	}
}

func list(con *lv.Connect) {
	doms, err := con.ListAllDomains(lv.CONNECT_LIST_DOMAINS_ACTIVE)
	if err != nil {
		panic(err)
	}

	fmt.Printf("%d running domains:\n", len(doms))
	for _, d := range doms {
		name, err := d.GetName()
		id, err := d.GetID()
		if err == nil {
			fmt.Printf("%d  %s\n", id, name)
		}

		d.Free()
	}
}
