package main

import (
	"log"
	"os/exec"
)

func run(arg []string, quiet bool) error {
	log.Printf("command: %s", arg)
	cmd := exec.Command(arg[0])
	cmd.Args = arg
	out, err := cmd.CombinedOutput()
	if err != nil && !quiet {
		log.Printf("%s", out)
	}

	return err
}
