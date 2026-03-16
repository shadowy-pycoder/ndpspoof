//go:build !linux && !(android && arm)

package ndpspoof

import "net"

func NewDNSServer() (net.PacketConn, error) {
	return nil, nil
}
