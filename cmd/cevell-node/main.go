package main

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/cevell/private-ai/pkg/attestation"
	"github.com/cevell/private-ai/pkg/auth"
	"github.com/cevell/private-ai/pkg/config"
	"github.com/cevell/private-ai/pkg/crypto"
	"github.com/cevell/private-ai/pkg/hardware"
	"github.com/cevell/private-ai/pkg/inference"
	"github.com/cevell/private-ai/pkg/network"
	"github.com/cevell/private-ai/pkg/proxy"
	"github.com/cevell/private-ai/pkg/system"
)

var (
	nodeKeyPair    *crypto.KeyPair
	nodeTLSCert    *tls.Certificate
	nodeTLSCertPEM []byte
	attestationDoc *attestation.AttestationDocument
	supervisor     *inference.Supervisor
	authVerifier   *auth.Ed25519Verifier
)

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "init":
			runNodeSupervisor()
			return
		case "version", "-v", "--version":
			fmt.Println("Cevell OS Node Supervisor v1.0.0 (Confidential AI)")
			fmt.Printf("Build Target: %s\n", config.GetTarget())
			return
		case "help", "-h", "--help":
			printUsage()
			return
		default:
			// Default to supervisor mode
			runNodeSupervisor()
			return
		}
	}
	runNodeSupervisor()
}

func printUsage() {
	fmt.Println("Usage: cevell-node [command]")
	fmt.Println()
	fmt.Println("Commands:")
	fmt.Println("  init          Start the full node lifecycle and confidential proxy (default)")
	fmt.Println("  version       Print version and build target information")
	fmt.Println("  help          Print usage instructions")
}

func runNodeSupervisor() {
	// Step 0: Resolve mandatory debug flag and enforce console lockdown
	debugOn, err := config.IsDebugMode()
	if err != nil {
		system.LogError("[FATAL CONFIGURATION ERROR] %v", err)
		panic(fmt.Sprintf("FATAL: Cevell OS cannot start: %v", err))
	}
	_ = system.ConfigureConsoleLockdown(debugOn)

	if debugOn {
		system.Log("==================================================")
		system.Log("   CEVELL OS NODE ENGINE — UNIFIED SUPERVISOR    ")
		system.Log("   [DEBUG MODE ACTIVE: SERIAL CONSOLE ENABLED]    ")
		system.Log("==================================================")
	}

	// Step 1: Early OS initialization
	_ = system.SetupFilesystems()
	_ = system.ApplyRuntimeLimits()
	_ = system.SetHostname("cevell-cvm")
	_ = system.BringUpLoopback()
	system.StartZombieReaper()

	// Step 2: Auto-Discover Hardware Topology
	topo := hardware.DiscoverTopology()
	if config.IsGPULocked() {
		if topo.HasGPU && topo.GPUCount > 0 {
			system.Log("[✓] GPU Accelerator Detected: %d physical GPU(s) active (%v). Initializing GPU-only inference runtime.",
				topo.GPUCount, topo.GPUDevices)
		} else {
			system.LogError("[FATAL HARDWARE MISMATCH] No physical GPU accelerator detected on PCIe bus or device tree! Node is in GPU-ONLY mode (CPU execution is strictly prohibited).")
		}
	} else {
		system.Log("[✓] Initializing CPU-optimized inference runtime (CPUs=%d, AVX512=%v, AVX2=%v, GPUs=%d).",
			topo.CPUCores, topo.HasAVX512, topo.HasAVX2, topo.GPUCount)
	}
	system.Log("Hardware Topology: Target=%s, CPUs=%d, RAM=%dMB, AVX512=%v, GPUs=%d (%v), Engine=%s",
		config.GetTarget(), topo.CPUCores, topo.RAMTotalMB, topo.HasAVX512, topo.GPUCount, topo.GPUDevices, topo.Recommended)

	// Step 3: Driver preloading
	system.Log("Preloading hardware & virtualization driver modules...")
	_ = system.PreloadDriverModules()

	// Step 4: Apply firewall BEFORE bringing up external network to eliminate exposure race window
	system.Log("Applying stateful nftables firewall policy...")
	if err := network.ApplyFirewallConfig("/etc/nftables.conf"); err != nil {
		system.LogError("[FATAL SECURITY FAILURE] Failed to apply firewall rules: %v", err)
		system.LogError("[HALT] PID 1 cannot exit (kernel panic). Halting in degraded state.")
		select {} // PID 1 must never return — that causes kernel panic
	}
	if err := system.LockKernelModules(); err != nil {
		system.LogError("[FATAL SECURITY FAILURE] Failed to lock kernel modules: %v", err)
		system.LogError("[HALT] PID 1 cannot exit (kernel panic). Halting in degraded state.")
		select {} // PID 1 must never return — that causes kernel panic
	}

	// Step 5: Network autoconfiguration with firewall active
	system.Log("Executing network discovery & DHCP lease acquisition...")
	iface, err := network.DiscoverAndConfigureNetwork(60 * time.Second)
	if err != nil {
		system.LogError("Network discovery warning: %v", err)
	} else if iface != nil {
		system.Log("Network active: %s (%s)", iface.Name, iface.IP.String())
	}

	// Step 5b: Latch Authorized Public Key from Instance Metadata / Environment / Config
	system.Log("Discovering and latching tenant authorized Ed25519 public key...")
	verifier, err := auth.NewDefaultEd25519Verifier()
	if err != nil {
		system.LogError("[FATAL SECURITY FAILURE] Failed to latch authorized tenant public key: %v", err)
		system.LogError("[HALT] PID 1 cannot exit (kernel panic). Node will fail closed until rebooted with valid cevell-auth-pub metadata.")
		select {}
	}
	authVerifier = verifier
	system.Log("[✓] Authorized Ed25519 Public Key Latched: %s", authVerifier.GetPublicKeyHex())

	// Step 6: Cryptographic key generation
	system.Log("Initializing node identity & ephemeral encryption keys...")
	keyPair, err := crypto.GenerateNodeKeyPair()
	if err != nil {
		system.LogError("Key generation failed: %v", err)
		system.LogError("[HALT] PID 1 cannot exit (kernel panic). Halting in degraded state.")
		select {}
	}
	nodeKeyPair = keyPair
	system.Log("Node SPKI SHA-256 Fingerprint: %x", keyPair.TLSKeyFP)
	system.Log("Node HPKE X25519 Public Key:  %x", keyPair.HPKEPubKey)

	// Step 7: Self-signed X.509 certificate generation
	var extraIPs []net.IP
	extraIPs = append(extraIPs, net.ParseIP("127.0.0.1"))
	if iface != nil && iface.IP != nil {
		extraIPs = append(extraIPs, iface.IP)
	}
	cert, certPEM, err := crypto.GenerateSelfSignedCert(keyPair.TLSKey, "cevell-cvm.internal", extraIPs)
	if err != nil {
		system.LogError("Certificate generation failed: %v", err)
		system.LogError("[HALT] PID 1 cannot exit (kernel panic). Halting in degraded state.")
		select {}
	}
	nodeTLSCert = cert
	nodeTLSCertPEM = certPEM

	// Step 8: Hardware attestation evidence collection
	system.Log("Collecting AMD SEV-SNP / Intel TDX / NVIDIA GPU hardware attestation report...")
	binding := attestation.BindingData{
		TLSKeyFingerprint: keyPair.TLSKeyFP,
		HPKEPublicKey:     keyPair.HPKEPubKey,
	}

	// Generate boot session nonce derived from node identity keys to ensure fresh, non-zero nonce
	bootNonce := sha256.Sum256(append(keyPair.TLSKeyFP[:], keyPair.HPKEPubKey[:]...))
	gpuEv, _ := attestation.CollectGPUEvidence(bootNonce)
	userData := attestation.ComputeCompositeUserData(keyPair.TLSKeyFP, keyPair.HPKEPubKey, bootNonce, gpuEv)
	rawReport, certChain, platform, err := attestation.FetchHardwareReport(userData)
	if err != nil {
		system.LogError("Hardware attestation report unavailable: %v", err)
		attestationDoc = nil
	} else {
		system.Log("Hardware attestation acquired on %s platform", platform)
		attestationDoc = attestation.BuildAttestationDocumentWithEvidence(binding, rawReport, certChain, platform, string(certPEM), hex.EncodeToString(bootNonce[:]), gpuEv)
		attestationDoc.Predicate.UserData = hex.EncodeToString(userData[:])
	}

	// Step 9: Initialize Inference Supervisor
	supervisor = inference.NewSupervisor(8000)

	// If in CPU mode, check if a pre-bundled model exists at /opt/models/model.gguf
	if !config.IsGPULocked() {
		if _, err := os.Stat("/opt/models/model.gguf"); err == nil {
			go func() {
				system.Log("Pre-bundled model found at /opt/models/model.gguf, auto-loading...")
				ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
				defer cancel()
				exposeInHealth := false
				_ = supervisor.LoadModel(ctx, inference.ModelSpec{
					Model:          "/opt/models/model.gguf",
					ExposeInHealth: &exposeInHealth,
				})
			}()
		}
	}

	// Step 10: Launch confidential proxy & inference gateway on port 443
	system.Log("Starting Cevell confidential HTTPS proxy & OpenAI gateway on port 443 [Launch-Provisioned Auth Mode]...")
	go func() {
		cfg := &proxy.ServerConfig{
			Port:           443,
			UpstreamURL:    "http://127.0.0.1:8000",
			KeyPair:        nodeKeyPair,
			TLSCert:        nodeTLSCert,
			TLSCertPEM:     nodeTLSCertPEM,
			AttestationDoc: attestationDoc,
			Supervisor:     supervisor,
			Verifier:       authVerifier,
		}
		if err := proxy.StartProxyServer(cfg); err != nil {
			system.LogError("Proxy server error: %v", err)
		}
	}()

	// Step 11: Keep PID 1 supervisor active
	select {}
}
