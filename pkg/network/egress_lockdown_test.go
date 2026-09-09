package network

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGenerateSealedNFTablesContent(t *testing.T) {
	content := GenerateSealedNFTablesContent()

	// 1. Must flush existing outbound_filter rules to replace cleanly
	assert.Contains(t, content, "flush chain inet firewall outbound_filter")

	// 2. Outbound policy must be drop
	assert.Contains(t, content, "type filter hook output priority 0; policy drop;")

	// 3. Loopback must be accepted for local proxy <-> vLLM IPC
	assert.Contains(t, content, "oifname \"lo\" accept")

	// 4. Established/related return traffic must be restricted to inbound streams (sport 443 or ct direction reply)
	assert.Contains(t, content, "tcp sport { 443 } ct state established,related accept")
	assert.Contains(t, content, "ct direction reply ct state established,related accept")

	// 5. DHCP client renewals must be accepted
	assert.Contains(t, content, "udp sport 68 udp dport 67 accept")

	// 6. Explicit IMDS block rules
	assert.Contains(t, content, "ip daddr 169.254.169.254 drop")
	assert.Contains(t, content, "ip6 daddr fd00:ec2::254 drop")
}

func TestApplySealedEgressPolicyFileWrite(t *testing.T) {
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "nftables-sealed.conf")

	err := os.WriteFile(configPath, []byte(GenerateSealedNFTablesContent()), 0600)
	require.NoError(t, err)

	data, err := os.ReadFile(configPath)
	require.NoError(t, err)
	assert.True(t, strings.Contains(string(data), "policy drop"))
}
