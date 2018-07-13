package main

import (
	"io/ioutil"
	"fmt"
	lxml "github.com/libvirt/libvirt-go-xml"
)


var uuid = "92fa824d-2a1e-435a-be3c-1a6b2f286c5f"

var xmldoc = "/vz/vmprivate/92fa824d-2a1e-435a-be3c-1a6b2f286c5f/config.xml"


func domanXml_() string {
	d, err := ioutil.ReadFile(xmldoc)
	if err != nil {
		panic(err)
	}

	fmt.Printf("%s\n", string(d))

	return string(d)
}

func domanXml() string {
	d := &lxml.Domain {
	Type: "qemu",
	Name: "test-vm",
	UUID: uuid,
	Memory: &lxml.DomainMemory {
		Value: 1024,
		Unit: "KiB",
	}, 
	Devices: &lxml.DomainDeviceList {
		Emulator: "/usr/libexec/qemu-tcmu",
	},
	OS: &lxml.DomainOS {
		Type: &lxml.DomainOSType {
			Type: "hvm",
		},
	},
	}

	xml, err := d.Marshal()
	if err != nil {
		fmt.Printf("Error")
		panic(err)
	}

	fmt.Printf("%s\n", xml)
	return xml
}
