package network

import (
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/cevell/private-ai/pkg/system"
)

// DefaultSealedNFTablesPath is the default path to write the sealed nftables configuration file.
// Uses /run (tmpfs) since rootfs /etc is read-only in dm-verity protected CVMs.
const DefaultSealedNFTablesPath = "/run/nftables-sealed.conf"

// GenerateSealedNFTablesContent returns the nftables ruleset string that flushes
// and replaces the outbound filter chain with an air-gapped drop-all policy.
// It explicitly preserves:
// 1. Loopback (lo) communication for intra-node IPC (cevell-node proxy <-> vLLM).
// 2. Return packets for established/related inbound connections on port 443 and ct direction reply (streaming response tokens to client).
// 3. DHCP keepalives (UDP sport 68 -> dport 67) to prevent IP lease expiration on cloud hypervisors.
// 4. Explicit drops for IMDS link-local endpoints (169.254.169.254 and fd00:ec2::254).
// All outbound-initiated connections (ct direction original) are dropped.
func GenerateSealedNFTablesContent() string {
	return `flush chain inet firewall outbound_filter
table inet firewall {
    chain outbound_filter {
        type filter hook output priority 0; policy drop;
        oifname "lo" accept
        tcp sport { 443 } ct state established,related accept
        ct direction reply ct state established,related accept
        udp sport 68 udp dport 67 accept
        ip daddr 169.254.169.254 drop
        ip6 daddr fd00:ec2::254 drop
    }
}
`
}

// ApplySealedEgressPolicy atomically replaces the outbound nftables chain
// with a policy that drops all outbound internet traffic. This is irreversible at runtime.
func ApplySealedEgressPolicy() error {
	return ApplySealedEgressPolicyWithConfig(DefaultSealedNFTablesPath)
}

// ApplySealedEgressPolicyWithConfig writes and applies the sealed ruleset to a specified path.
func ApplySealedEgressPolicyWithConfig(configPath string) error {
	content := GenerateSealedNFTablesContent()

	// Write to writable tmpfs if a path is provided
	if configPath != "" {
		_ = os.WriteFile(configPath, []byte(content), 0600)
	}

	// Apply via stdin pipe directly to avoid disk dependency
	cmd := exec.Command("nft", "-f", "-")
	cmd.Stdin = strings.NewReader(content)
	out, err := cmd.CombinedOutput()
	if err != nil {
		// Fallback to file-based execution if stdin pipe fails
		if configPath != "" {
			cmdFile := exec.Command("nft", "-f", configPath)
			_, errFile := cmdFile.CombinedOutput()
			if errFile == nil {
				// Sever any pre-existing outbound TCP connections and flush connection tracking entries
				_ = exec.Command("conntrack", "-F").Run()
				_ = exec.Command("ss", "-K", "state", "connected", "dst", "!127.0.0.1").Run()
				system.Log("[SEAL] Outbound egress firewall locked down via file (%s)", configPath)
				return nil
			}
		}
		return fmt.Errorf("applying sealed egress policy: %w\nOutput: %s", err, string(out))
	}

	// Sever any pre-existing outbound TCP connections and flush connection tracking entries
	_ = exec.Command("conntrack", "-F").Run()
	_ = exec.Command("ss", "-K", "state", "connected", "dst", "!127.0.0.1").Run()

	system.Log("[SEAL] Outbound egress firewall locked down: all external internet access blocked")
	return nil
}
