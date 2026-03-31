package main

import (
	"flag"
	"fmt"
	"net/netip"
	"os"
	"os/signal"
	"regexp"
	"runtime"
	"slices"
	"strings"
	"time"

	"github.com/rs/zerolog"
	"github.com/shadowy-pycoder/colors"
	"github.com/shadowy-pycoder/mshark/network"
	"github.com/shadowy-pycoder/ndpspoof"
)

var (
	app           = "nf"
	ipPortPattern = regexp.MustCompile(
		`(?:(?:\[(?:[0-9a-fA-F:.]+(?:%[a-zA-Z0-9_.-]+)?)\]|(?:\d{1,3}\.){3}\d{1,3})(?::(6553[0-5]|655[0-2]\d|65[0-4]\d{2}|6[0-4]\d{3}|[1-5]?\d{1,4}))?|(?:[0-9a-fA-F:]+:+[0-9a-fA-F:]+(?:%[a-zA-Z0-9_.-]+)?))`,
	)
	macPattern = regexp.MustCompile(
		`(?i)(?:\b[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}\b|\b[0-9a-f]{2}-[0-9a-f]{2}-[0-9a-f]{2}-[0-9a-f]{2}-[0-9a-f]{2}-[0-9a-f]{2}\b|\b[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}\b|\b[a-z0-9_]+_[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}\b)`,
	)
)

const usageHeader string = `nf - IPv6 NDP spoofing tool by shadowy-pycoder

GitHub: https://github.com/shadowy-pycoder/ndpspoof
Codeberg: https://codeberg.org/shadowy-pycoder/ndpspoof

Usage: nf [-h -v -I -d -nocolor -auto -i INTERFACE -interval DURATION] [-na -f -t ADDRESS ... -g ADDRESS]
          [-ra -p PREFIX -mtu INT -rlt DURATION -rdnss ADDRESS ... -E PACKET]
OPTIONS:
  General:
  -h           Show this help message and exit
  -v           Show version and build information
  -I           Display list of network interfaces and exit
  -d           Enable debug logging
  -nocolor     Disable colored output
  -auto        Automatically set kernel parameters (Linux/Android) and network settings. When RA spoofing is enabled and no -rdnss flag
               is provided, RDNSS option is included in each packet with host IP as DNS server for targets. DNS server is setup using
               resolv.conf or Google DNS as fallback nameserver.
  -i           The name of the network interface. Example: eth0 (Default: default interface)
  -interval    Interval between sent packets (Default: 5s)

  NA spoofing:
  -na          Enable NA (neighbor advertisement) spoofing mode
  -t           Targets for NA spoofing. (Example: "fe80::3a1c:7bff:fe22:91a4,fe80::b6d2:4cff:fe9a:5f10")
  -f           Fullduplex mode (send messages to targets and router)
  -g           IPv6 address of custom gateway (Default: default gateway)

  RA spoofing:
  -ra          Enable RA (router advertisement) spoofing. It is enabled when no spoofing mode specified
  -p           IPv6 prefix for RA spoofing (Example: 2001:db8:7a31:4400::/64). See RFC 4862 for more info
  -mtu         MTU value to send in RA packet (Default: interface value)
  -rlt         Router lifetime value. Tells targets how long router should be used as default gateway. See RFC 4682 for more info
  -rdnss       Comma separated list of DNS servers for RDNSS mode (Example: "2001:4860:4860::8888,2606:4700:4700::1111")
  -E           Specify IPv6 extension headers for RA Guard evasion. The packet structure should contain at least one fragment (F)
               that is used to separate per-fragment headers (PFH) and headers for fragmentable part. PFH get included in each fragment,
               all other headers become part of fragmentable payload. See RFC 8200 section 4.5 to learn more about fragment header.

               Supported extension headers:

                   H - Hop-by-Hop Options Header
                   D - Destination Options Header
                   S - Routing Header (Type 0) (Note: See RFC 5095)
                   R - Routing Header (Type 2)
                   F - Fragment Header
                   L - One-shot Fragment Header
                   N - No Next Header

               Each header can be specified multiple times (e.g. HHDD) or you can add number to specify count (e.g. H16).
               The maximum number of consecutive headers of one type is 16 (H16H2F will not work, but H16DH2F will). The
               minimum number of consecutive headers is 1 (e.g. H0 will cause error).

               The exception to this rule is D header where number means header size (e.g. D255 is maximum size).
               You can still specify multiple D headers (e.g. D255D2D23). No next header count is ignored by design,
               but you can add multiple N headers between other headers (e.g. HNDR F DN).

               There are no limits where or how much headers to add to packet structure, but certain limits exist:

                   Maximum payload length for IPv6 is 65535 bytes
                   Maximum fragment offset is 8191 octet words
                   Minimum IPv6 MTU is 1280 bytes

               Note that fragment count you specify may be changed automatically to satisfy limits and 8 byte alignment requirement.
               If you are not sure how many fragments you want, just do not specify any count.

               Examples:

                   F2 DSDS (same as atk6-fake_router26 -E F)
                   FD154 (same as atk6-fake_router26 -E D)
                   HLLLF (same as atk6-fake_router26 -E H111)
                   HDR F2 D255 (just random structure)
                   F (single letter F means regular RA packet)

               As you can see, some examples mention atk6-fake_router26 which is part of The Hacker Choice's IPv6 Attack Toolkit (thc-ipv6).
               Unlike thc-ipv6, ndpspoof (nf) tool does not offer predefined attack types, but you can construct them yourself.
`

func root(args []string) error {
	conf := &ndpspoof.NDPSpoofConfig{}
	flags := flag.NewFlagSet(app, flag.ExitOnError)
	flags.BoolVar(&conf.NA, "na", false, "")
	flags.BoolVar(&conf.RA, "ra", false, "")
	flags.BoolVar(&conf.FullDuplex, "f", false, "")
	flags.BoolVar(&conf.Debug, "d", false, "")

	if slices.Contains(ndpspoof.AutoConfigSupportedOS, runtime.GOOS) {
		flags.BoolVar(&conf.Auto, "auto", false, "")
	}
	flags.BoolFunc("v", "", func(flagValue string) error {
		fmt.Printf("%s (built for %s %s with %s)\n", ndpspoof.Version, runtime.GOOS, runtime.GOARCH, runtime.Version())
		os.Exit(0)
		return nil
	})
	flags.StringVar(&conf.Targets, "t", "", "")
	flags.StringVar(&conf.RDNSS, "rdnss", "", "")
	gw := flags.String("g", "", "")
	flags.StringVar(&conf.Interface, "i", "", "")
	nocolor := flags.Bool("nocolor", false, "")
	flags.BoolFunc("I", "", func(flagValue string) error {
		if err := network.DisplayInterfaces(false); err != nil {
			fmt.Fprintf(os.Stderr, "%s: %v\n", app, err)
			os.Exit(2)
		}
		os.Exit(0)
		return nil
	})
	flags.DurationVar(&conf.RouterLifetime, "rlt", time.Duration(600*time.Second), "")
	flags.DurationVar(&conf.PacketInterval, "interval", time.Duration(5*time.Second), "")
	mtu := flags.Uint("mtu", 0, "")
	prefix := flags.String("p", "", "")
	flags.StringVar(&conf.PacketQuery, "E", "", "")
	flags.Usage = func() {
		fmt.Print(usageHeader)
	}
	if err := flags.Parse(args); err != nil {
		return err
	}
	if conf.NA {
		if *gw != "" {
			ip, err := netip.ParseAddr(*gw)
			if err != nil {
				return err
			}
			conf.Gateway = &ip
		}
		if conf.Targets == "" {
			return fmt.Errorf("list of targets is empty")
		}
	}
	if !conf.RA && !conf.NA {
		conf.RA = true
	}
	if !conf.RA && conf.RDNSS != "" {
		return fmt.Errorf("rdnss requires ra enabled")
	}
	if conf.RA {
		if *prefix != "" {
			pval, err := netip.ParsePrefix(*prefix)
			if err != nil {
				return err
			}
			if !network.Is6(pval.Addr()) {
				return fmt.Errorf("prefix is not valid IPv6 address")
			}
			conf.Prefix = &pval
		}
		if conf.RouterLifetime.Seconds() > 65535 {
			return fmt.Errorf("router lifetime is invalid")
		}
		if *mtu > 1<<32-1 {
			return fmt.Errorf("mtu value is out of range")
		} else if *mtu > 0 {
			conf.MTU = uint32(*mtu)
		}
	}
	output := zerolog.ConsoleWriter{Out: os.Stdout, NoColor: *nocolor}
	output.FormatTimestamp = func(i any) string {
		ts, _ := time.Parse(time.RFC3339, i.(string))
		if *nocolor {
			return colors.WrapBrackets(ts.Format(time.TimeOnly))
		}
		return colors.Gray(colors.WrapBrackets(ts.Format(time.TimeOnly))).String()
	}
	output.FormatMessage = func(i any) string {
		if i == nil || i == "" {
			return ""
		}
		s := i.(string)
		if *nocolor {
			return s
		}
		result := ipPortPattern.ReplaceAllStringFunc(s, func(match string) string {
			if macPattern.MatchString(match) {
				return match
			}
			return colors.Gray(match).String()
		})
		result = macPattern.ReplaceAllStringFunc(result, func(match string) string {
			return colors.Yellow(match).String()
		})
		return result
	}
	output.FormatErrFieldValue = func(i any) string {
		s := i.(string)
		if *nocolor {
			return s
		}
		result := ipPortPattern.ReplaceAllStringFunc(s, func(match string) string {
			if macPattern.MatchString(match) {
				return match
			}
			return colors.Red(match).String()
		})
		result = strings.ReplaceAll(result, "->", "→ ")
		return result
	}
	logger := zerolog.New(output).With().Timestamp().Logger()
	conf.Logger = &logger
	ndpspoofer, err := ndpspoof.NewNDPSpoofer(conf)
	if err != nil {
		return err
	}
	go ndpspoofer.Start()
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt)
	<-quit
	return ndpspoofer.Stop()
}

func main() {
	if err := root(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "%s: %v\n", app, err)
		os.Exit(2)
	}
}
