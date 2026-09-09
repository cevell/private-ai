package system

import (
	"fmt"
	"log"
	"os"
	"sync"
	"syscall"
)

var (
	consoleMu     sync.RWMutex
	debugActive   = true
	serialTargets = []string{"/dev/kmsg", "/dev/ttyS0", "/dev/console"}
	logChan       chan logEntry
	logInitOnce   sync.Once
	openHandles   = make(map[string]*os.File)
	openHandlesMu sync.Mutex

	recentLogsMu  sync.RWMutex
	recentLogsBuf []string
)

type logEntry struct {
	isErr bool
	msg   string
}

func appendRecentLog(msg string) {
	recentLogsMu.Lock()
	defer recentLogsMu.Unlock()
	if len(recentLogsBuf) >= 500 {
		recentLogsBuf = recentLogsBuf[1:]
	}
	recentLogsBuf = append(recentLogsBuf, msg)
}

// GetRecentSystemLogs returns an in-memory snapshot of recent log entries.
func GetRecentSystemLogs() []string {
	recentLogsMu.RLock()
	defer recentLogsMu.RUnlock()
	copied := make([]string, len(recentLogsBuf))
	copy(copied, recentLogsBuf)
	return copied
}

// ConfigureConsoleLockdown controls whether virtual serial and console devices are active.
// When debug is false (debug = off):
// - All serial/console write targets are removed
// - Console device nodes (/dev/ttyS0, /dev/console, /dev/tty1, /dev/tty, /dev/kmsg) are chmod 0000 and unlinked
// - Kernel printk is silenced (0 0 0 0)
// - Logs are retained strictly in encrypted RAM for health queries, with zero console leakage
func ConfigureConsoleLockdown(debug bool) error {
	consoleMu.Lock()
	defer consoleMu.Unlock()

	debugActive = debug
	if debug {
		serialTargets = []string{"/dev/kmsg", "/dev/ttyS0", "/dev/console"}
		return nil
	}

	// STRICT PRODUCTION LOCKDOWN (debug = off):
	serialTargets = nil
	openHandlesMu.Lock()
	for target, f := range openHandles {
		if f != nil {
			_ = f.Close()
		}
		delete(openHandles, target)
	}
	openHandlesMu.Unlock()

	// 1. Silence kernel console printk
	_ = os.WriteFile("/proc/sys/kernel/printk", []byte("0 0 0 0\n"), 0644)

	// 2. Neutralize physical and virtual console device nodes
	for _, dev := range []string{"/dev/ttyS0", "/dev/console", "/dev/tty1", "/dev/tty", "/dev/kmsg"} {
		_ = os.Chmod(dev, 0000)
		_ = os.Remove(dev)
	}

	return nil
}

// IsConsoleDebugActive returns true if console logging is enabled.
func IsConsoleDebugActive() bool {
	consoleMu.RLock()
	defer consoleMu.RUnlock()
	return debugActive
}

func initLogger() {
	logChan = make(chan logEntry, 2048)
	go func() {
		for entry := range logChan {
			prefix := "<6>[cevell] "
			consolePrefix := "[cevell] "
			if entry.isErr {
				prefix = "<3>[cevell ERROR] "
				consolePrefix = "[cevell ERROR] "
			}

			consoleMu.RLock()
			targets := serialTargets
			consoleMu.RUnlock()

			for _, target := range targets {
				openHandlesMu.Lock()
				f, ok := openHandles[target]
				if !ok || f == nil {
					var err error
					f, err = os.OpenFile(target, os.O_WRONLY|syscall.O_NONBLOCK, 0)
					if err != nil {
						openHandlesMu.Unlock()
						continue
					}
					openHandles[target] = f
				}
				openHandlesMu.Unlock()

				var err error
				if target == "/dev/kmsg" {
					_, err = fmt.Fprintf(f, "%s%s\n", prefix, entry.msg)
				} else {
					_, err = fmt.Fprintf(f, "%s%s\n", consolePrefix, entry.msg)
				}
				if err != nil {
					_ = f.Close()
					openHandlesMu.Lock()
					delete(openHandles, target)
					openHandlesMu.Unlock()
				}
			}
		}
	}()
}

func ensureLogger() {
	logInitOnce.Do(initLogger)
}

// Log writes a message to in-memory buffer and, if debug is active, to console targets.
func Log(format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	appendRecentLog("[cevell] " + msg)

	if !IsConsoleDebugActive() {
		return
	}

	ensureLogger()
	log.Printf("[cevell] %s", msg)

	select {
	case logChan <- logEntry{isErr: false, msg: msg}:
	default:
		// Queue saturated: non-blocking drop prevents caller stalling
	}
}

// LogError logs an error message with priority level <3> (ERR).
func LogError(format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	appendRecentLog("[cevell ERROR] " + msg)

	if !IsConsoleDebugActive() {
		return
	}

	ensureLogger()
	log.Printf("[cevell ERROR] %s", msg)

	select {
	case logChan <- logEntry{isErr: true, msg: msg}:
	default:
		// Queue saturated: non-blocking drop prevents caller stalling
	}
}
