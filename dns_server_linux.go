//go:build linux || (android && arm)

package ndpspoof

import (
	"context"
	"net"
	"syscall"

	"golang.org/x/sys/unix"
)

func newDNSServer() (net.PacketConn, error) {
	lc := net.ListenConfig{
		Control: func(network, address string, conn syscall.RawConn) error {
			var operr error
			size := 2 * 1024 * 1024
			if err := conn.Control(func(fd uintptr) {
				operr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEADDR, 1)
				operr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_SNDBUF, size)
				operr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_RCVBUF, size)
			}); err != nil {
				return err
			}
			return operr
		},
	}
	return lc.ListenPacket(context.Background(), "udp", ":53")
}
