package performance

import (
	"fmt"
	"os/exec"
	"strings"
)

type skopeoOp struct {
	username  string
	password  string
	address   string
	tlsVerify bool
	repo      string
}

func checkSkopeoBinary() bool {
	err := exec.Command("skopeo", "--version").Run()
	if err != nil {
		return false
	}

	return true
}

func setCopyCommand(op skopeoOp) []string {
	args := []string{"copy"}
	args = append(args, "--insecure-policy")

	if !op.tlsVerify {
		args = append(args, "--dest-tls-verify=false")
		args = append(args, "--src-tls-verify=false")
	}

	return args
}

func setCommandVariables(op skopeoOp, args []string, src string, dest string, isZotPush bool) []string {
	if isZotPush {
		creds := fmt.Sprintf("--dest-creds=%s:%s", op.username, op.password)
		args = append(args, creds)
		args = append(args, fmt.Sprintf("oci:images/%s", src))
		args = append(args,
			fmt.Sprintf("docker://%s/%s/%s", op.address, op.repo, dest))
	} else {
		args = append(args, fmt.Sprintf("--src-creds=%s:%s", op.username, op.password))
		args = append(args,
			fmt.Sprintf("docker://%s/%s/%s", op.address, op.repo, src))
		args = append(args, fmt.Sprintf("oci:oci-images/%s", dest))
	}

	return args
}

func runCopy(op skopeoOp, src string, dest string, isZotPush bool) bool {
	args := setCopyCommand(op)
	args = setCommandVariables(op, args, src, dest, isZotPush)
	cmd := exec.Command("skopeo", args...)
	err := cmd.Start()

	if err != nil {
		return false
	}

	err = cmd.Wait()
	if err != nil {
		return false
	}

	return true
}

func setPushCommand(op skopeoOp, imageName string) []string {
	args := []string{"copy"}
	args = append(args, "--insecure-policy")
	args = append(args, "--dest-creds")
	args = append(args, fmt.Sprintf("%s:%s", op.username, op.password))

	if !op.tlsVerify {
		args = append(args, "--dest-tls-verify=false")
		args = append(args, "--src-tls-verify=false")
	}

	args = append(args, fmt.Sprintf("oci:images/%s", imageName))
	args = append(args, fmt.Sprintf("docker://%s/%s/%s:latest", op.address, op.repo, imageName))

	return args
}

func runPushCommand(op skopeoOp, imageName string) bool {
	args := setPushCommand(op, imageName)
	cmd := exec.Command("skopeo", args...)
	err := cmd.Start()

	if err != nil {
		return false
	}

	err = cmd.Wait()
	if err != nil {
		return false
	}

	return true
}

func setDeleteCommand(op skopeoOp, imageName string) []string {
	args := []string{"delete"}
	creds := fmt.Sprintf("--creds=%s:%s", op.username, op.password)
	args = append(args, creds)

	if !op.tlsVerify {
		args = append(args, "--tls-verify=false")
	}

	args = append(args, fmt.Sprintf("docker://%s/%s/%s", op.address, op.repo, imageName))

	return args
}

func runDeleteCommand(op skopeoOp, imageName string) bool {
	args := setDeleteCommand(op, imageName)
	cmd := exec.Command("skopeo", args...)
	err := cmd.Start()

	if err != nil {
		return false
	}

	err = cmd.Wait()
	if err != nil {
		return false
	}

	return true
}

func runCommands(commands []string) bool {
	processes := make(map[*exec.Cmd]bool)
	for _, args := range commands {
		cmd := exec.Command("skopeo", strings.Fields(args)...)
		processes[cmd] = true

		if err := cmd.Start(); err != nil {
			return false
		}
	}

	for process := range processes {
		if err := process.Wait(); err != nil {
			return false
		}
	}

	return true
}
