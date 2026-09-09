package network

import (
	"fmt"
	"os"
	"os/exec"

	"github.com/cevell/private-ai/pkg/system"
)

// ApplyFirewallConfig applies the specified nftables configuration ruleset.
func ApplyFirewallConfig(configPath string) error {
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		// If custom file does not exist, write default secure configuration
		if err := writeDefaultNFTables(configPath); err != nil {
			return err
		}
	}

	cmd := exec.Command("nft", "-f", configPath)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("applying nftables (%s): %w\nOutput: %s", configPath, err, string(out))
	}

	system.Log("Firewall policy applied successfully from %s", configPath)
	return nil
}

func writeDefaultNFTables(path string) error {
	content := `table inet firewall {
    chain inbound_filter {
        type filter hook input priority 0; policy drop;
        iifname "lo" accept
        ct state established,related accept
        ct state invalid drop
        ip protocol icmp accept
        ip6 nexthdr icmpv6 accept
        udp sport 67 udp dport 68 accept
        tcp dport { 443 } accept
    }
    chain forward_filter {
        type filter hook forward priority 0; policy drop;
        ct state established,related accept
    }
    chain outbound_filter {
        type filter hook output priority 0; policy accept;
    }
}
`
	return os.WriteFile(path, []byte(content), 0644)
}
