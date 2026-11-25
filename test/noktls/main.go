//go:build linux

// Command noktls runs a command as if the kernel had no TLS upper layer
// protocol, even when the tls module is loaded and cannot be unloaded (e.g.
// it is held by a NIC driver such as mlx5_core, as on Azure-hosted runners).
//
//	go run ./test/noktls -- make run-blackbox-ktls
//
// It installs a seccomp filter that fails setsockopt(IPPROTO_TCP, TCP_ULP)
// with ENOENT, the errno a kernel without the module returns, then execs the
// command. The filter is inherited by every child process, so zot started
// from a test script sees kTLS as unavailable and keeps TLS in userspace.
// Nothing else is affected: TCP_ULP is only used to attach kTLS (or mptcp
// subflows, which these tests never set up).
package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

// Offsets into struct seccomp_data: int nr; __u32 arch; __u64
// instruction_pointer; __u64 args[6]. Only the low 32 bits of each argument
// are compared, which covers level and optname (both C ints); every
// architecture handled below is little-endian.
const (
	offNR    = 0
	offArch  = 4
	offArg1  = 16 + 1*8 // level
	offArg2  = 16 + 2*8 // optname
	retAllow = unix.SECCOMP_RET_ALLOW
	retNoULP = unix.SECCOMP_RET_ERRNO | uint32(unix.ENOENT)
)

var (
	errUsage        = errors.New("usage: noktls [--] command [args...]")
	errArch         = errors.New("noktls: unsupported architecture")
	errULPReachable = errors.New("noktls: TCP_ULP still reachable after filtering")
)

func auditArch() (uint32, error) {
	switch runtime.GOARCH {
	case "amd64":
		return unix.AUDIT_ARCH_X86_64, nil
	case "arm64":
		return unix.AUDIT_ARCH_AARCH64, nil
	default:
		return 0, fmt.Errorf("%w %s", errArch, runtime.GOARCH)
	}
}

func filter(arch uint32) []unix.SockFilter {
	const (
		ldAbs = unix.BPF_LD | unix.BPF_W | unix.BPF_ABS
		jeq   = unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K
		ret   = unix.BPF_RET | unix.BPF_K
	)

	// Each jeq falls through on a match and otherwise jumps to the final
	// ALLOW; jf is the number of instructions to skip to get there.
	return []unix.SockFilter{
		{Code: ldAbs, K: offArch},
		{Code: jeq, K: arch, Jf: 7}, // another ABI: not ours to judge
		{Code: ldAbs, K: offNR},
		{Code: jeq, K: unix.SYS_SETSOCKOPT, Jf: 5},
		{Code: ldAbs, K: offArg1},
		{Code: jeq, K: unix.IPPROTO_TCP, Jf: 3},
		{Code: ldAbs, K: offArg2},
		{Code: jeq, K: unix.TCP_ULP, Jf: 1},
		{Code: ret, K: retNoULP},
		{Code: ret, K: retAllow},
	}
}

func install() error {
	arch, err := auditArch()
	if err != nil {
		return err
	}

	prog := filter(arch)
	//nolint:gosec // G115: the filter is a fixed 10 instructions
	fprog := unix.SockFprog{Len: uint16(len(prog)), Filter: &prog[0]}

	// Required to install a filter without CAP_SYS_ADMIN; it also stops the
	// command from gaining privileges through setuid binaries (sudo).
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		return fmt.Errorf("noktls: PR_SET_NO_NEW_PRIVS: %w", err)
	}

	// TSYNC applies the filter to every thread of the Go runtime, so it
	// holds whichever thread ends up calling execve.
	if _, _, errno := unix.Syscall(unix.SYS_SECCOMP, unix.SECCOMP_SET_MODE_FILTER,
		unix.SECCOMP_FILTER_FLAG_TSYNC, uintptr(unsafe.Pointer(&fprog))); errno != 0 {
		return fmt.Errorf("noktls: seccomp: %w", errno)
	}

	runtime.KeepAlive(prog)

	return nil
}

// verify checks that the filter holds: attaching the ULP to an unconnected
// socket must now fail with ENOENT, not the ENOTCONN of a kTLS kernel.
func verify() error {
	sock, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("noktls: socket: %w", err)
	}

	defer func() { _ = unix.Close(sock) }()

	err = unix.SetsockoptString(sock, unix.IPPROTO_TCP, unix.TCP_ULP, "tls")
	if !errors.Is(err, unix.ENOENT) {
		return fmt.Errorf("%w: setsockopt returned %v", errULPReachable, err) //nolint:errorlint // nil is a valid value here
	}

	return nil
}

func run(args []string) error {
	if len(args) > 0 && args[0] == "--" {
		args = args[1:]
	}

	if len(args) == 0 {
		return errUsage
	}

	path, err := exec.LookPath(args[0])
	if err != nil {
		return err
	}

	if err := install(); err != nil {
		return err
	}

	if err := verify(); err != nil {
		return err
	}

	return syscall.Exec(path, args, os.Environ()) //nolint:gosec // running the given command is the point
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
}
