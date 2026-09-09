package system

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

// PreloadDriverModules preloads all mandatory AWS Nitro, virtualization, container networking,
// cryptography, and netfilter kernel drivers before runtime module loading is permanently locked.
func PreloadDriverModules() error {
	baseDrivers := []string{
		// Linux Kernel Crypto API (LKCA) - Mandatory for NVIDIA GSP / SPDM / DICE verification
		"ecdsa_generic",
		"ecrdsa_generic",
		"aesni-intel",
		"aesni_intel",
		"ghash-clmulni-intel",
		"ghash_clmulni_intel",
		"cmac",
		"ccm",
		"authenc",
		"authencesn",
		"cryptd",
		"crypto_engine",
		"crypto_user",
		"af_alg",
		"algif_hash",
		"algif_skcipher",
		"algif_aead",
		"algif_rng",
		"pkcs8_key_parser",
		"chacha20poly1305",
		"aegis128-aesni",
		"sm3_generic",
		"sm4_generic",

		// AMD SEV-SNP & Intel TDX Confidential Computing
		"sev-guest",
		"tdx-guest",
		"tdx_guest",
		"tsm_report",
		"intel_rapl_msr",
		"configfs",

		// Cloud Virtualization & Hypervisor (GCP / AWS / Azure / QEMU)
		"gve",
		"idpf",
		"virtio_net",
		"virtio_pci",
		"virtio_blk",
		"virtio_scsi",
		"virtio_balloon",
		"virtio_console",
		"ena",
		"ptp_vmclock",
		"i2c_piix4",
		"cpuid",
		"msr",

		// DRM, PCI & VFIO Core Drivers
		"drm",
		"drm_buddy",
		"drm_gpuvm",
		"drm_gpusvm_helper",
		"drm_vram_helper",
		"drm_suballoc_helper",
		"drm_ttm_helper",
		"drm_display_helper",
		"drm_exec",
		"gpu-sched",
		"virtio-gpu",
		"i2c-nvidia-gpu",
		"vfio",
		"vfio_iommu_type1",
		"vfio_pci",
	}

	loadedCount := 0
	for _, mod := range baseDrivers {
		cmd := exec.Command("modprobe", mod)
		if out, err := cmd.CombinedOutput(); err == nil {
			loadedCount++
			Log("Kernel driver loaded: %s", mod)
		} else {
			Log("Modprobe %s: %v (Output: %s)", mod, err, stringsTrim(string(out)))
		}
	}

	// Load NVIDIA proprietary/open GPU kernel drivers AFTER core crypto & DRM
	LoadDirectNVIDIAModules()

	// Ensure accelerator device directory hierarchies and character nodes
	_ = EnsureGPUDeviceNodes()

	// Permanently hold GPU adapter context and enable Persistence Mode BEFORE anything else
	_ = HoldNVIDIAPersistence()
	_ = exec.Command("nvidia-smi", "-pm", "1").Run()

	_ = VerifyNVIDIAAdapterHealth()

	networkingAndSecurityDrivers := []string{
		// Container Networking & Virtualization
		"overlay",
		"veth",
		"bridge",
		"br_netfilter",
		"macvlan",
		"ipvlan",
		"tap",
		"dummy",

		// Netfilter / Firewall / NAT Drivers
		"nfnetlink",
		"nf_tables",
		"nft_compat",
		"nft_chain_nat",
		"nf_conntrack",
		"nf_defrag_ipv4",
		"nf_defrag_ipv6",
		"nft_ct",
		"nft_fib",
		"nft_fib_ipv4",
		"nft_fib_inet",
		"nf_nat",
		"nft_nat",
		"nft_masq",
		"nft_reject",
		"nft_reject_inet",
		"nft_reject_ipv4",
		"ip_tables",
		"iptable_filter",
		"iptable_nat",
		"x_tables",
		"xt_nat",
		"xt_conntrack",
		"xt_addrtype",
		"xt_MASQUERADE",
	}

	for _, mod := range networkingAndSecurityDrivers {
		cmd := exec.Command("modprobe", mod)
		if out, err := cmd.CombinedOutput(); err == nil {
			loadedCount++
			Log("Kernel driver loaded: %s", mod)
		} else {
			Log("Modprobe %s: %v (Output: %s)", mod, err, stringsTrim(string(out)))
		}
	}

	// Re-verify accelerator device directory hierarchies and character nodes
	_ = EnsureGPUDeviceNodes()

	// Transition NVIDIA Confidential Computing GPUs to Ready State & enable persistence mode
	_ = InitializeGPUConfidentialComputing()

	Log("Kernel driver preloading complete (%d/%d drivers loaded via kmod)", loadedCount, len(baseDrivers)+len(networkingAndSecurityDrivers))
	return nil
}

var nvidiaDevFiles []*os.File

// HoldNVIDIAPersistence opens and permanently holds /dev/nvidiactl and /dev/nvidia0 open so the
// Linux kernel and GSP firmware do not drop the GPU adapter context between user-space queries.
func HoldNVIDIAPersistence() error {
	if len(nvidiaDevFiles) > 0 {
		return nil
	}
	for _, devPath := range []string{"/dev/nvidiactl", "/dev/nvidia0"} {
		if _, err := os.Stat(devPath); err == nil {
			f, err := os.OpenFile(devPath, os.O_RDWR, 0)
			if err != nil {
				f, err = os.Open(devPath)
			}
			if err == nil {
				nvidiaDevFiles = append(nvidiaDevFiles, f)
				Log("NVIDIA GPU persistence context anchor held open (%s)", devPath)
			} else {
				Log("Warning: unable to hold %s persistence: %v", devPath, err)
			}
		}
	}
	return nil
}

// InitializeGPUConfidentialComputing sets the Ready State on NVIDIA Confidential Computing GPUs.
func InitializeGPUConfidentialComputing() error {
	if _, err := os.Stat("/dev/nvidiactl"); err == nil {
		// 1. Permanently hold GPU adapter context and enable Persistence Mode
		_ = HoldNVIDIAPersistence()
		_ = exec.Command("nvidia-smi", "-pm", "1").Run()

		// 2. Set Confidential Compute Ready State
		cmd := exec.Command("nvidia-smi", "conf-compute", "-srs", "1")
		if out, err := cmd.CombinedOutput(); err == nil {
			Log("NVIDIA CC Ready State initialized successfully: %s", stringsTrim(string(out)))
		}
	}
	return nil
}

const sysFinitModule = 313 // Linux x86_64 finit_module(2) syscall number

// finitModuleSyscall invokes the Linux finit_module(2) system call.
func finitModuleSyscall(fd uintptr, params string, flags int) error {
	cparams, err := syscall.BytePtrFromString(params)
	if err != nil {
		return err
	}
	_, _, errno := syscall.Syscall(
		sysFinitModule,
		fd,
		uintptr(unsafe.Pointer(cparams)),
		uintptr(flags),
	)
	if errno != 0 {
		return errno
	}
	return nil
}

// LoadDirectNVIDIAModules loads out-of-tree NVIDIA proprietary/open drivers using finit_module syscall.
func LoadDirectNVIDIAModules() {
	moduleDirs := []string{
		"/lib/modules/7.0.0-1006-aws/kernel/drivers/video",
		"/lib/modules/7.0.0-1006-aws/updates/dkms",
		"/usr/lib/cevell/kernel-modules",
		"/lib/modules",
		"/usr/lib/modules",
	}

	modules := []struct {
		name   string
		file   string
		params string
	}{
		{"nvidia", "nvidia.ko", "NVreg_EnableGpuFirmware=1 NVreg_OpenRmEnableUnsupportedGpus=1 NVreg_RegistryDwords=RMEnableGspOnAllGpus=1 NVreg_PreserveVideoMemoryAllocations=1"},
		{"nvidia_modeset", "nvidia-modeset.ko", ""},
		{"nvidia_uvm", "nvidia-uvm.ko", ""},
	}

	for _, m := range modules {
		if _, err := os.Stat("/sys/module/" + m.name); err == nil {
			Log("NVIDIA driver module %s already active in sysfs", m.name)
			continue
		}

		loaded := false
		for _, dir := range moduleDirs {
			path := dir + "/" + m.file
			if f, err := os.Open(path); err == nil {
				err = finitModuleSyscall(f.Fd(), m.params, 0)
				f.Close()
				if err == nil || err == syscall.EEXIST {
					Log("NVIDIA module %s loaded successfully via finit_module from %s", m.name, path)
					loaded = true
					break
				} else {
					Log("finit_module %s failed: %v", path, err)
				}
			}
		}
		if !loaded {
			_ = exec.Command("modprobe", m.name).Run()
		}
	}
}

// VerifyNVIDIAAdapterHealth checks NVIDIA driver health and reloads drivers if unrecoverable.
func VerifyNVIDIAAdapterHealth() error {
	hasGPU, _ := hasNVIDIAHardware()
	if !hasGPU {
		return nil
	}

	// If persistence is held, the adapter context is anchored open and active.
	if len(nvidiaDevFiles) > 0 {
		return nil
	}

	// If persistence could not be anchored, attempt a clean reload.
	Log("NVIDIA adapter persistence not active, attempting driver reload...")

	for _, f := range nvidiaDevFiles {
		if f != nil {
			_ = f.Close()
		}
	}
	nvidiaDevFiles = nil

	_ = exec.Command("rmmod", "nvidia_uvm").Run()
	_ = exec.Command("rmmod", "nvidia_modeset").Run()
	_ = exec.Command("rmmod", "nvidia").Run()

	time.Sleep(500 * time.Millisecond)

	LoadDirectNVIDIAModules()
	_ = EnsureGPUDeviceNodes()
	_ = HoldNVIDIAPersistence()
	_ = exec.Command("nvidia-smi", "-pm", "1").Run()

	if len(nvidiaDevFiles) > 0 {
		Log("NVIDIA adapter health restored after driver reload")
		return nil
	}
	err := fmt.Errorf("unable to anchor NVIDIA persistence after reload")
	Log("NVIDIA adapter health check still failing after reload: %v", err)
	return err
}

// hasNVIDIAHardware checks if an NVIDIA PCI device (vendor 0x10de) or loaded driver is present.
func hasNVIDIAHardware() (bool, int) {
	if detectMajorFromProcDevices("nvidia") != 0 {
		if matches, err := filepath.Glob("/proc/driver/nvidia/gpus/*"); err == nil && len(matches) > 0 {
			return true, len(matches)
		}
		return true, 1
	}
	count := 0
	if vendors, err := filepath.Glob("/sys/bus/pci/devices/*/vendor"); err == nil {
		for _, vPath := range vendors {
			if data, err := os.ReadFile(vPath); err == nil {
				if strings.EqualFold(strings.TrimSpace(string(data)), "0x10de") {
					count++
				}
			}
		}
	}
	if count > 0 {
		return true, count
	}
	return false, 0
}

// EnsureGPUDeviceNodes verifies device hierarchies and creates character device nodes for NVIDIA GPUs.
func EnsureGPUDeviceNodes() error {
	_ = os.MkdirAll("/dev/dri", 0755)
	_ = os.MkdirAll("/dev/accel", 0755)
	_ = os.MkdirAll("/dev/nvidia-caps", 0755)

	hasGPU, count := hasNVIDIAHardware()
	if !hasGPU {
		// Pure CPU mode: do not create phantom /dev/nvidiaX nodes
		return nil
	}
	if count <= 0 {
		count = 1
	}
	if count > 8 {
		count = 8
	}

	// Standard NVIDIA character device nodes (Major 195)
	nvidiaNodes := []struct {
		path  string
		major uint32
		minor uint32
	}{
		{"/dev/nvidiactl", 195, 255},
		{"/dev/nvidia-modeset", 195, 254},
	}
	for i := 0; i < count; i++ {
		nvidiaNodes = append(nvidiaNodes, struct {
			path  string
			major uint32
			minor uint32
		}{
			path:  fmt.Sprintf("/dev/nvidia%d", i),
			major: 195,
			minor: uint32(i),
		})
	}

	for _, node := range nvidiaNodes {
		maj := uint64(node.major)
		min := uint64(node.minor)
		dev := int((maj&0xfff)<<8 | (min & 0xff) | ((maj &^ 0xfff) << 32) | ((min &^ 0xff) << 12))
		_ = syscall.Mknod(node.path, syscall.S_IFCHR|0660, dev)
		_ = os.Chmod(node.path, 0660)
		if os.Getuid() == 0 {
			_ = os.Chown(node.path, 0, 998)
		}
	}

	// Dynamic detection for nvidia-uvm from /proc/devices
	var uvmMajor uint32
	for attempt := 0; attempt < 3; attempt++ {
		uvmMajor = detectMajorFromProcDevices("nvidia-uvm")
		if uvmMajor == 0 {
			uvmMajor = detectMajorFromProcDevices("nvidia_uvm")
		}
		if uvmMajor != 0 {
			break
		}
		if attempt < 2 {
			Log("nvidia-uvm not yet registered in /proc/devices, retrying in 500ms (attempt %d/3)...", attempt+1)
			time.Sleep(500 * time.Millisecond)
		}
	}
	if uvmMajor == 0 {
		return fmt.Errorf("nvidia-uvm driver not found in /proc/devices after 3 attempts: cannot create dynamic character device")
	}

	uMaj := uint64(uvmMajor)
	dev0 := int((uMaj&0xfff)<<8 | (0 & 0xff) | ((uMaj &^ 0xfff) << 32))
	_ = os.Remove("/dev/nvidia-uvm")
	_ = syscall.Mknod("/dev/nvidia-uvm", syscall.S_IFCHR|0660, dev0)
	_ = os.Chmod("/dev/nvidia-uvm", 0660)
	if os.Getuid() == 0 {
		_ = os.Chown("/dev/nvidia-uvm", 0, 998)
	}

	dev1 := int((uMaj&0xfff)<<8 | (1 & 0xff) | ((uMaj &^ 0xfff) << 32))
	_ = os.Remove("/dev/nvidia-uvm-tools")
	_ = syscall.Mknod("/dev/nvidia-uvm-tools", syscall.S_IFCHR|0660, dev1)
	_ = os.Chmod("/dev/nvidia-uvm-tools", 0660)
	if os.Getuid() == 0 {
		_ = os.Chown("/dev/nvidia-uvm-tools", 0, 998)
	}

	// Verify device nodes exist and ensure 0660 permissions
	allNodes := []string{
		"/dev/nvidiactl",
		"/dev/nvidia-modeset",
		"/dev/nvidia0",
		"/dev/nvidia1",
		"/dev/nvidia2",
		"/dev/nvidia3",
		"/dev/nvidia4",
		"/dev/nvidia5",
		"/dev/nvidia6",
		"/dev/nvidia7",
		"/dev/nvidia-uvm",
		"/dev/nvidia-uvm-tools",
	}
	for _, devPath := range allNodes {
		if _, err := os.Stat(devPath); err == nil {
			_ = os.Chmod(devPath, 0660)
			if os.Getuid() == 0 {
				_ = os.Chown(devPath, 0, 998)
			}
		}
	}

	if matches, err := filepath.Glob("/dev/nvidia-caps/*"); err == nil {
		for _, capPath := range matches {
			_ = os.Chmod(capPath, 0660)
			if os.Getuid() == 0 {
				_ = os.Chown(capPath, 0, 998)
			}
		}
	}

	return nil
}

func detectMajorFromProcDevices(name string) uint32 {
	data, err := os.ReadFile("/proc/devices")
	if err != nil {
		return 0
	}
	lines := strings.Split(string(data), "\n")
	altName := strings.ReplaceAll(name, "-", "_")
	altNameDash := strings.ReplaceAll(name, "_", "-")
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) >= 2 && (fields[1] == name || fields[1] == altName || fields[1] == altNameDash) {
			var major uint32
			if _, err := fmt.Sscanf(fields[0], "%d", &major); err == nil {
				return major
			}
		}
	}
	return 0
}

func stringsTrim(s string) string {
	if len(s) > 100 {
		return s[:100]
	}
	return s
}

// LockKernelModules permanently disables runtime kernel module insertion by writing 1 to
// /proc/sys/kernel/modules_disabled, ensuring kernel integrity and preventing rootkits.
func LockKernelModules() error {
	if err := os.WriteFile("/proc/sys/kernel/modules_disabled", []byte("1\n"), 0644); err != nil {
		return fmt.Errorf("failed to lock kernel modules: %w", err)
	}
	Log("Kernel modules locked successfully (/proc/sys/kernel/modules_disabled = 1)")
	return nil
}
