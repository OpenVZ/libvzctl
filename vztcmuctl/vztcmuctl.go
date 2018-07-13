package main

import (
	"flag"
	"os"
)

const ID = "disk_1024_e2971f868b5744469ad3ecebd87d8edc"
const IMAGE = "/vz/private/1024/root1.hdd"

func start(id string, image string) error {
	err := startService(id, image)
	if err != nil {
		return err
	}

	return tgSetup(id, image)
}

func stop(id string) {
	tgCleanup(id)
	stopService(id);
}

func main() {
	action := flag.String("c", "add", "Action add|del")
	id := flag.String("d", ID, "ID")
	image := flag.String("i", IMAGE, "Image")
	flag.Parse()

	var err error
	if *action == "add" {
		err = start(*id, *image)
		if err != nil {
			stop(*id)
		}
	} else if *action == "del" {
		stop(*id)
	} else {
		tgInfo(*id)
	}

	if err != nil {
		os.Exit(1)
	}
}

