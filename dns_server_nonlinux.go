//go:build !linux && !(android && arm)

package ndpspoof

import "net"

func newDNSServer() (net.PacketConn, error) {
	return nil, nil
}
