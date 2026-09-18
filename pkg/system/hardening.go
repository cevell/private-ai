package system

import (
	"os"
	"os/exec"
	"os/signal"
	"syscall"

	"golang.org/x/sys/unix"
)

// SetHostname configures the system hostname.
func SetHostname(name string) error {
	return syscall.Sethostname([]byte(name))
}

// ApplyRuntimeLimits configures secure runtime resource limits (file descriptors, process count).
func ApplyRuntimeLimits() error {
	_ = os.Setenv("PATH", "/usr/bin:/usr/sbin:/bin:/sbin")
	_ = os.Setenv("HOME", "/mnt/ramdisk/home")

	var nofile unix.Rlimit
	nofile.Cur = 1048576
	nofile.Max = 1048576
	if err := unix.Setrlimit(unix.RLIMIT_NOFILE, &nofile); err != nil {
		Log("Warning: unable to set RLIMIT_NOFILE: %v", err)
	}

	var nproc unix.Rlimit
	nproc.Cur = 65536
	nproc.Max = 65536
	if err := unix.Setrlimit(unix.RLIMIT_NPROC, &nproc); err != nil {
		Log("Warning: unable to set RLIMIT_NPROC: %v", err)
	}

	return nil
}

// SetupFilesystems mounts necessary pseudo-filesystems (/proc, /sys, /dev, /dev/shm, /dev/pts, /run, /tmp, /mnt/ramdisk) securely.
func SetupFilesystems() error {
	mounts := []struct {
		source string
		target string
		fstype string
		flags  uintptr
		data   string
	}{
		{"proc", "/proc", "proc", syscall.MS_NOSUID | syscall.MS_NODEV | syscall.MS_NOEXEC, ""},
		{"sysfs", "/sys", "sysfs", syscall.MS_NOSUID | syscall.MS_NODEV | syscall.MS_NOEXEC, ""},
		{"devtmpfs", "/dev", "devtmpfs", syscall.MS_NOSUID, "mode=0755"},
		{"devpts", "/dev/pts", "devpts", syscall.MS_NOSUID | syscall.MS_NOEXEC, "mode=0620,ptmxmode=0666"},
		{"configfs", "/sys/kernel/config", "configfs", syscall.MS_NOSUID | syscall.MS_NODEV | syscall.MS_NOEXEC, ""},
		{"tmpfs", "/run", "tmpfs", syscall.MS_NOSUID | syscall.MS_NODEV, "mode=0755"},
		{"tmpfs", "/tmp", "tmpfs", syscall.MS_NOSUID | syscall.MS_NODEV, "mode=1777"},
		{"tmpfs", "/var/tmp", "tmpfs", syscall.MS_NOSUID | syscall.MS_NODEV, "mode=1777"},
		{"tmpfs", "/dev/shm", "tmpfs", syscall.MS_NOSUID | syscall.MS_NODEV, "mode=1777"},
		{"tmpfs", "/mnt/ramdisk", "tmpfs", syscall.MS_NOSUID | syscall.MS_NODEV, "mode=0777,size=85%"},
		{"tmpfs", "/var/cache", "tmpfs", syscall.MS_NOSUID | syscall.MS_NODEV, "mode=0755"},
	}

	for _, m := range mounts {
		_ = os.MkdirAll(m.target, 0755)
		if err := syscall.Mount(m.source, m.target, m.fstype, m.flags, m.data); err != nil {
			if err != syscall.EBUSY {
				Log("Mount %s on %s: %v", m.source, m.target, err)
			}
		}
	}

	_ = os.Chmod("/tmp", 01777)
	_ = os.Chmod("/var/tmp", 01777)
	_ = os.Chmod("/dev/shm", 01777)

	// Create writable working directories on ramdisk
	_ = os.MkdirAll("/mnt/ramdisk/home", 0755)
	_ = os.MkdirAll("/mnt/ramdisk/cache", 0755)
	_ = os.MkdirAll("/mnt/ramdisk/models", 0755)
	_ = os.MkdirAll("/mnt/ramdisk/vllm", 0755)
	_ = os.MkdirAll("/mnt/ramdisk/tmp", 01777)
	_ = os.Chmod("/mnt/ramdisk/tmp", 01777)
	_ = os.MkdirAll("/run/systemd", 0755)

	if os.Getuid() == 0 {
		_ = os.Chown("/mnt/ramdisk/home", 1000, 1000)
		_ = os.Chown("/mnt/ramdisk/cache", 1000, 1000)
		_ = os.Chown("/mnt/ramdisk/models", 1000, 1000)
		_ = os.Chown("/mnt/ramdisk/vllm", 1000, 1000)
		_ = os.Chown("/mnt/ramdisk/tmp", 1000, 1000)
	}

	// Ensure default resolv.conf in /run/resolv.conf
	defaultResolv := "nameserver 169.254.169.253\nnameserver 1.1.1.1\nnameserver 1.0.0.1\n"
	_ = os.WriteFile("/run/resolv.conf", []byte(defaultResolv), 0644)

	return nil
}

// BringUpLoopback brings up the loopback network interface.
func BringUpLoopback() error {
	_ = exec.Command("/bin/busybox", "ip", "link", "set", "lo", "up").Run()
	_ = exec.Command("/usr/bin/ip", "link", "set", "lo", "up").Run()
	return nil
}

// StartZombieReaper registers a SIGCHLD signal handler to reap orphaned child processes.
// When cevell-node runs as PID 1 in the CVM, background child processes whose parents terminate
// (such as tensor parallel workers or background inference daemons) reparent to PID 1.
// Without an active non-blocking wait4 reaper, these processes accumulate indefinitely as defunct zombies.
func StartZombieReaper() {
	if os.Getpid() != 1 {
		return
	}
	SpawnZombieReaper()
}

// SpawnZombieReaper starts the reaping loop unconditionally on SIGCHLD.
func SpawnZombieReaper() {
	sigCh := make(chan os.Signal, 64)
	signal.Notify(sigCh, syscall.SIGCHLD)
	go func() {
		for range sigCh {
			for {
				var ws syscall.WaitStatus
				pid, err := syscall.Wait4(-1, &ws, syscall.WNOHANG, nil)
				if pid <= 0 || err != nil {
					break
				}
			}
		}
	}()
}

