package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"path/filepath"
	"regexp"
	"os"
	"os/exec"
	"strings"
	"strconv"
	"time"
)

const TG = "/usr/bin/targetcli"
const QEMU_IMG = "/usr/bin/qemu-img"
const NAA = "naa.1234567890123456"

func getImageSize(image string) (uint64, error) {
	var dat map[string]interface{}

	out, err := exec.Command(QEMU_IMG, "info", "--output=json", "--force", image).Output()
	if err != nil {
		log.Println("Failed to get image size:", image, out, err)
		return 0,  err
	}

	err = json.Unmarshal(out, &dat)
	if err != nil {
		log.Println("Cannot parse", out, err)
		return 0, err
	}

	size := uint64(dat["virtual-size"].(float64))
	log.Printf("Image %s size=%v\n", image, size)
	return size, err
}

func tgWait(id string) error {
	var err error
	for t := 1; t < 4; t++ {
		err = run([]string {TG, "ls", "/backstores/user:" + id}, false) 
		if err == nil {
			return err
		}
		time.Sleep(time.Second)
	}

	return err
}

func tgSetup(id string, img string) error {
	log.Println("Setup target:", id)

	size, err := getImageSize(img)
	if err != nil {
		return err
	}

	err = tgWait(id)
	if err != nil {
		return err
	}

	s := "/sys/kernel/config/target/loopback/" + NAA
	_, err = os.Stat(s)
	if os.IsNotExist(err) {
		err = run([]string {TG, "/loopback/", "create", NAA}, false)
		if err != nil {
			return err
		}
	}

	err = run([]string {TG, "/backstores/user:" + id, "create",
		"name=" + id, "size=" + strconv.FormatUint(size, 10),
		"cfgstring=drive0"}, false)
	if err != nil {
		return err
	}

	err = run([]string {TG, "/loopback/" + NAA + "/luns", "create",
		"storage_object=/backstores/user:" + id + "/" + id}, false)
	if err != nil {
		return err
	}

	tgInfo(id)

	return err
}

func tgCleanup(id string) error {
	log.Println("Cleanup target ", id)
	out, err := exec.Command(TG,  "/loopback/" + NAA + "/luns", "ls").Output()
	if err != nil {
		log.Println("Failed list loopback luns:", err)
		return err
	}

	r := "(lun\\d).*" + id
	re, err := regexp.Compile(r)
	res := re.FindStringSubmatch(string(out))
	if len(res) > 1 {
		run([]string {TG, "/loopback/$NAA/luns", "delete", res[1]}, false)
	}

	err = run([]string {TG, "/backstores/user:" + id + "/" + id, "ls"}, true)
	if err == nil {
		run([]string {TG, "/backstores/user:" + id, "delete", id}, false)
	}

	return nil
}

func getSerial(id string) string {
	files, err := ioutil.ReadDir("/sys/kernel/config/target/core")
	if err != nil {
		log.Println(err)
		return ""
	}

	
	for _, file := range files {
		f := "/sys/kernel/config/target/core/" + file.Name() + "/" + id + "/wwn/vpd_unit_serial"
		out, err := ioutil.ReadFile(f)
		if err != nil {
			continue
		}

		re, _ := regexp.Compile("Serial Number:\\s(.*)")
		res := re.FindStringSubmatch(string(out))
		if len(res) > 1 {
			serial := strings.Replace(res[1], "-", "", -1)
			if len(serial) > 25 {
				serial = serial[:25]
			}
			return serial
		}
	}

	return ""
}

func getDevice(serial string) string {
	files, err := ioutil.ReadDir("/dev/disk/by-id")
	if err != nil {
		log.Println(err)
		return ""
	}

	for _, file := range files {
		re, err := regexp.Compile("scsi-........" + serial + "$")
		if err != nil {
			log.Fatal(err)
		}
		if !re.MatchString(string(file.Name())) {
			continue
		}
		lnk, err := os.Readlink("/dev/disk/by-id/" + file.Name())
		if err != nil {
			continue
		}

		dev, _ := filepath.Abs("/dev/disk/by-id/" + lnk)
		fmt.Printf("\"device\": \"%s\"\n", dev)

		return dev
	}
	return ""
}

func tgInfo(id string) string {
	var serial string
	for t := 1; t < 4; t++ {
		serial = getSerial(id)
		if serial != "" {
			break
		}
		time.Sleep(time.Second)
	}

	return getDevice(serial)
}
