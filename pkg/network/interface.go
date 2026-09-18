package network

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/cevell/private-ai/pkg/system"
	"golang.org/x/sys/unix"
)

// PrimaryInterface represents the active external network interface.
type PrimaryInterface struct {
	Name     string
	IP       net.IP
	Hardware net.HardwareAddr
}

// DiscoverAndConfigureNetwork brings up external network interfaces and acquires DHCP leases.
func DiscoverAndConfigureNetwork(timeout time.Duration) (*PrimaryInterface, error) {
	deadline := time.Now().Add(timeout)

	for time.Now().Before(deadline) {
		candidateNames := findNetworkInterfaces()
		for _, ifaceName := range candidateNames {
			system.Log("Evaluating candidate network interface: %s", ifaceName)

			// Bring interface UP
			_ = exec.Command("ip", "link", "set", "dev", ifaceName, "up").Run()

			// Check interface via net.InterfaceByName
			netIface, err := net.InterfaceByName(ifaceName)
			if err != nil {
				time.Sleep(500 * time.Millisecond)
				continue
			}

			// Check if already has an IPv4 address
			addrs, _ := netIface.Addrs()
			for _, addr := range addrs {
				if ipNet, ok := addr.(*net.IPNet); ok && !ipNet.IP.IsLoopback() && ipNet.IP.To4() != nil {
					system.Log("Active network interface ready: %s (IP: %s)", ifaceName, ipNet.IP.String())
					return &PrimaryInterface{
						Name:     ifaceName,
						IP:       ipNet.IP,
						Hardware: netIface.HardwareAddr,
					}, nil
				}
			}

			// Strategy 1: Busybox udhcpc via direct binary
			system.Log("Attempting DHCP lease via busybox udhcpc on interface %s...", ifaceName)
			udhcpcCmd := exec.Command("/bin/busybox", "udhcpc", "-i", ifaceName, "-n", "-q", "-t", "8", "-T", "3", "-s", "/usr/share/udhcpc/default.script")
			if out, err := udhcpcCmd.CombinedOutput(); err == nil {
				system.Log("udhcpc lease acquired successfully on %s:\n%s", ifaceName, string(out))
				_ = os.MkdirAll("/run", 0755)
				if _, err := os.Stat("/etc/resolv.conf"); err != nil {
					_ = os.WriteFile("/etc/resolv.conf", []byte("nameserver 1.1.1.1\nnameserver 8.8.8.8\n"), 0644)
				}

				// Verify acquired IP
				if updatedIface, err := net.InterfaceByName(ifaceName); err == nil {
					if upAddrs, err := updatedIface.Addrs(); err == nil {
						for _, addr := range upAddrs {
							if ipNet, ok := addr.(*net.IPNet); ok && !ipNet.IP.IsLoopback() && ipNet.IP.To4() != nil {
								return &PrimaryInterface{
									Name:     ifaceName,
									IP:       ipNet.IP,
									Hardware: updatedIface.HardwareAddr,
								}, nil
							}
						}
					}
				}
			} else {
				system.Log("udhcpc on %s: %v (output: %s)", ifaceName, err, strings.TrimSpace(string(out)))
			}

			// Strategy 2: Raw socket DHCP client
			system.Log("Attempting raw socket DHCP on interface %s...", ifaceName)
			ip, maskLen, gateway, err := obtainDHCP(ifaceName)
			if err == nil && ip != nil {
				system.Log("DHCP acquired successfully: IP=%s/%d Gateway=%s", ip.String(), maskLen, gateway.String())
				cidr := fmt.Sprintf("%s/%d", ip.String(), maskLen)
				_ = exec.Command("ip", "addr", "add", cidr, "dev", ifaceName).Run()
				if gateway != nil && gateway.String() != "0.0.0.0" {
					_ = exec.Command("ip", "route", "add", gateway.String(), "dev", ifaceName).Run()
					_ = exec.Command("ip", "route", "add", "default", "via", gateway.String(), "dev", ifaceName, "onlink").Run()
				}
				_ = os.MkdirAll("/run", 0755)
				dnsContent := "nameserver 1.1.1.1\nnameserver 8.8.8.8\n"
				if gateway != nil && gateway.String() != "0.0.0.0" {
					dnsContent = fmt.Sprintf("nameserver %s\nnameserver 1.1.1.1\nnameserver 8.8.8.8\n", gateway.String())
				}
				_ = os.WriteFile("/run/resolv.conf", []byte(dnsContent), 0644)
				_ = os.WriteFile("/etc/resolv.conf", []byte(dnsContent), 0644)

				return &PrimaryInterface{
					Name:     ifaceName,
					IP:       ip,
					Hardware: netIface.HardwareAddr,
				}, nil
			} else {
				system.Log("Raw DHCP probe on %s: %v", ifaceName, err)
			}
		}
		time.Sleep(1 * time.Second)
	}

	return nil, fmt.Errorf("timeout waiting for network interface after %v", timeout)
}

func findNetworkInterfaces() []string {
	seen := make(map[string]bool)
	var names []string

	// 1. Check /sys/class/net
	if entries, err := os.ReadDir("/sys/class/net"); err == nil {
		for _, e := range entries {
			name := e.Name()
			if isExternalInterface(name) && !seen[name] {
				seen[name] = true
				names = append(names, name)
			}
		}
	}

	// 2. Check /sys/bus/pci/devices/*/net/*
	if matches, err := filepath.Glob("/sys/bus/pci/devices/*/net/*"); err == nil {
		for _, m := range matches {
			name := filepath.Base(m)
			if isExternalInterface(name) && !seen[name] {
				seen[name] = true
				names = append(names, name)
			}
		}
	}

	// 3. Check net.Interfaces()
	if ifaces, err := net.Interfaces(); err == nil {
		for _, iface := range ifaces {
			name := iface.Name
			if isExternalInterface(name) && !seen[name] {
				seen[name] = true
				names = append(names, name)
			}
		}
	}

	return names
}

func isExternalInterface(name string) bool {
	if name == "lo" || strings.HasPrefix(name, "dummy") || strings.HasPrefix(name, "docker") || strings.HasPrefix(name, "veth") || strings.HasPrefix(name, "br-") {
		return false
	}
	return true
}

func htons(v uint16) uint16 {
	return (v << 8) | (v >> 8)
}

func ipChecksum(b []byte) uint16 {
	var sum uint32
	for i := 0; i < len(b)-1; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(b[i : i+2]))
	}
	if len(b)%2 == 1 {
		sum += uint32(b[len(b)-1]) << 8
	}
	for (sum >> 16) > 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

func buildEthernetIPv4UDP(srcMAC net.HardwareAddr, payload []byte) []byte {
	ethLen := 14
	ipLen := 20
	udpLen := 8
	totalLen := ethLen + ipLen + udpLen + len(payload)
	frame := make([]byte, totalLen)

	for i := 0; i < 6; i++ {
		frame[i] = 0xff
	}
	copy(frame[6:12], srcMAC)
	frame[12] = 0x08
	frame[13] = 0x00

	ipStart := ethLen
	frame[ipStart] = 0x45
	binary.BigEndian.PutUint16(frame[ipStart+2:ipStart+4], uint16(ipLen+udpLen+len(payload)))
	var ipID [2]byte
	_, _ = rand.Read(ipID[:])
	binary.BigEndian.PutUint16(frame[ipStart+4:ipStart+6], binary.BigEndian.Uint16(ipID[:]))
	frame[ipStart+8] = 64
	frame[ipStart+9] = 17
	for i := 0; i < 4; i++ {
		frame[ipStart+16+i] = 0xff
	}
	csum := ipChecksum(frame[ipStart : ipStart+20])
	binary.BigEndian.PutUint16(frame[ipStart+10:ipStart+12], csum)

	udpStart := ethLen + ipLen
	binary.BigEndian.PutUint16(frame[udpStart:udpStart+2], 68)
	binary.BigEndian.PutUint16(frame[udpStart+2:udpStart+4], 67)
	binary.BigEndian.PutUint16(frame[udpStart+4:udpStart+6], uint16(udpLen+len(payload)))

	copy(frame[udpStart+8:], payload)
	return frame
}

func obtainDHCP(ifaceName string) (net.IP, int, net.IP, error) {
	_ = exec.Command("ip", "link", "set", "dev", ifaceName, "up").Run()

	netIface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return nil, 0, nil, fmt.Errorf("interface %s: %w", ifaceName, err)
	}

	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, int(htons(unix.ETH_P_ALL)))
	if err != nil {
		return nil, 0, nil, err
	}
	defer unix.Close(fd)

	sall := &unix.SockaddrLinklayer{
		Ifindex:  netIface.Index,
		Protocol: htons(unix.ETH_P_ALL),
		Halen:    6,
	}
	for i := 0; i < 6; i++ {
		sall.Addr[i] = 0xff
	}
	if err := unix.Bind(fd, sall); err != nil {
		return nil, 0, nil, err
	}

	tv := unix.NsecToTimeval(int64(2 * time.Second))
	_ = unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv)

	var xidBytes [4]byte
	if _, err := rand.Read(xidBytes[:]); err != nil {
		binary.BigEndian.PutUint32(xidBytes[:], uint32(time.Now().UnixNano()))
	}
	xid := binary.BigEndian.Uint32(xidBytes[:])
	mac := netIface.HardwareAddr
	if len(mac) < 6 {
		return nil, 0, nil, fmt.Errorf("invalid MAC length for %s", ifaceName)
	}

	discover := make([]byte, 300)
	discover[0] = 1
	discover[1] = 1
	discover[2] = 6
	binary.BigEndian.PutUint32(discover[4:8], xid)
	discover[10] = 0x80
	copy(discover[28:34], mac)
	copy(discover[236:240], []byte{0x63, 0x82, 0x53, 0x63})
	discover[240] = 53
	discover[241] = 1
	discover[242] = 1
	discover[243] = 55
	discover[244] = 3
	discover[245] = 1
	discover[246] = 3
	discover[247] = 6
	discover[248] = 255

	frame := buildEthernetIPv4UDP(mac, discover[:300])

	var offerIP net.IP
	var subnetMask net.IPMask = net.CIDRMask(24, 32)
	var router net.IP
	var serverID net.IP

	buf := make([]byte, 2048)
	for attempt := 0; attempt < 5; attempt++ {
		_ = unix.Sendto(fd, frame, 0, sall)

		deadline := time.Now().Add(2 * time.Second)
		for time.Now().Before(deadline) {
			n, _, err := unix.Recvfrom(fd, buf, 0)
			if err != nil {
				break
			}
			if n < 282 {
				continue
			}
			if buf[12] != 0x08 || buf[13] != 0x00 {
				continue
			}
			ipHeaderLen := int((buf[14] & 0x0f) * 4)
			if ipHeaderLen < 20 || 14+ipHeaderLen+8 > n {
				continue
			}
			if buf[14+9] != 17 {
				continue
			}
			udpStart := 14 + ipHeaderLen
			dstPort := binary.BigEndian.Uint16(buf[udpStart+2 : udpStart+4])
			if dstPort != 68 {
				continue
			}
			dhcpStart := udpStart + 8
			if dhcpStart+240 > n {
				continue
			}
			recvXID := binary.BigEndian.Uint32(buf[dhcpStart+4 : dhcpStart+8])
			if recvXID != xid {
				continue
			}
			if !bytes.Equal(buf[dhcpStart+236:dhcpStart+240], []byte{0x63, 0x82, 0x53, 0x63}) {
				continue
			}

			offerIP = net.IPv4(buf[dhcpStart+16], buf[dhcpStart+17], buf[dhcpStart+18], buf[dhcpStart+19])
			opts := buf[dhcpStart+240 : n]
			i := 0
			msgType := byte(0)
			for i < len(opts) {
				opt := opts[i]
				if opt == 0 {
					i++
					continue
				}
				if opt == 255 {
					break
				}
				if i+1 >= len(opts) {
					break
				}
				optLen := int(opts[i+1])
				if i+2+optLen > len(opts) {
					break
				}
				optData := opts[i+2 : i+2+optLen]
				if opt == 53 && optLen == 1 {
					msgType = optData[0]
				} else if opt == 1 && optLen == 4 {
					subnetMask = net.IPv4Mask(optData[0], optData[1], optData[2], optData[3])
				} else if opt == 3 && optLen >= 4 {
					router = net.IPv4(optData[0], optData[1], optData[2], optData[3])
				} else if opt == 54 && optLen >= 4 {
					serverID = net.IPv4(optData[0], optData[1], optData[2], optData[3])
				}
				i += 2 + optLen
			}

			if msgType == 2 && router != nil {
				break
			}
		}

		if router != nil && offerIP != nil {
			break
		}
	}

	if router == nil || offerIP == nil {
		return nil, 0, nil, fmt.Errorf("no valid DHCP offer received")
	}

	targetServer := router
	if serverID != nil {
		targetServer = serverID
	}

	ones, _ := subnetMask.Size()

	request := make([]byte, 300)
	request[0] = 1
	request[1] = 1
	request[2] = 6
	binary.BigEndian.PutUint32(request[4:8], xid)
	request[10] = 0x80
	copy(request[28:34], mac)
	copy(request[236:240], []byte{0x63, 0x82, 0x53, 0x63})
	request[240] = 53
	request[241] = 1
	request[242] = 3
	request[243] = 50
	request[244] = 4
	copy(request[245:249], offerIP.To4())
	request[249] = 54
	request[250] = 4
	copy(request[251:255], targetServer.To4())
	request[255] = 255

	reqFrame := buildEthernetIPv4UDP(mac, request[:300])
	_ = unix.Sendto(fd, reqFrame, 0, sall)

	return offerIP, ones, router, nil
}
