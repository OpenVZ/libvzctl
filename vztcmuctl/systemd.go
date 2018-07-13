package main

const SYSTEMD_RUN = "/usr/bin/systemd-run"
const SYSTEMCTL = "/usr/bin/systemctl"
const QEMU_TCMU = "/usr/libexec/qemu-tcmu"

func startService(id string, img string) error {
	cmd := []string {SYSTEMD_RUN, "--unit=" + id, QEMU_TCMU,
		"-M", "accel=tcg", "-nographic", "-nodefaults",
		"-device", "tcmu-blk,drive=drive0",
		"-device", "tcmu,subtype=" + id,
		"-drive", "id=drive0,if=none,file=" + img}

	return run(cmd, false)
}

func stopService(id string) error {
	cmd := []string {SYSTEMCTL, "stop", id}

	rc := run(cmd, false)
	if rc != nil {
		cmd[1] = "reset-failed"
		rc = run(cmd, false)
	}

	return rc
}
