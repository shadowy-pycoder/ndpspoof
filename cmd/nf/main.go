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

func root(args []string) error {
	conf := &ndpspoof.NDPSpoofConfig{}
	flags := flag.NewFlagSet(app, flag.ExitOnError)
	flags.BoolVar(&conf.NA, "na", false, "Enable NA (neighbor advertisement) spoofing")
	flags.BoolVar(&conf.RA, "ra", false, "Enable RA (router advertisement) spoofing. It is enabled when no spoof mode specified)")
	flags.BoolVar(&conf.RDNSS, "rdnss", false, "Enable RDNSS spoofing. Enabling this option requires -dns-servers flag")
	flags.BoolVar(&conf.FullDuplex, "f", false, "Run NA spoofing in fullduplex mode")
	flags.BoolVar(&conf.Debug, "d", false, "Enable debug logging")

	if slices.Contains(ndpspoof.AutoConfigSupportedOS, runtime.GOOS) {
		flags.BoolVar(&conf.Auto, "auto", false, "Automatically set kernel parameters and network settings for spoofing")
	}
	flags.BoolFunc("v", "Show version and build information", func(flagValue string) error {
		fmt.Printf("%s (built for %s %s with %s)\n", ndpspoof.Version, runtime.GOOS, runtime.GOARCH, runtime.Version())
		os.Exit(0)
		return nil
	})
	flags.StringVar(
		&conf.Targets,
		"t",
		"",
		"Targets for NA spoofing. Example: \"fe80::3a1c:7bff:fe22:91a4,fe80::b6d2:4cff:fe9a:5f10\"",
	)
	flags.StringVar(
		&conf.DNSServers,
		"dns-servers",
		"",
		"Comma separated list of DNS servers for RDNSS mode. Example: \"2001:4860:4860::8888,2606:4700:4700::1111\"",
	)
	gw := flags.String("g", "", "IPv6 address of custom gateway (Default: default gateway)")
	flags.StringVar(&conf.Interface, "i", "", "The name of the network interface. Example: eth0 (Default: default interface)")
	nocolor := flags.Bool("nocolor", false, "Disable colored output")
	flags.BoolFunc("I", "Display list of interfaces and exit.", func(flagValue string) error {
		if err := network.DisplayInterfaces(false); err != nil {
			fmt.Fprintf(os.Stderr, "%s: %v\n", app, err)
			os.Exit(2)
		}
		os.Exit(0)
		return nil
	})
	flags.DurationVar(&conf.RouterLifetime, "rlt", time.Duration(600*time.Second), "Router lifetime for RA spoofing")
	flags.DurationVar(&conf.PacketInterval, "interval", time.Duration(5*time.Second), "Interval between sent packets")
	if err := flags.Parse(args); err != nil {
		return err
	}
	prefix := flags.String("p", "", "IPv6 prefix for RA spoofing")
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
	if !conf.RA && conf.RDNSS {
		return fmt.Errorf("rdnss requires ra enabled")
	}
	if conf.RDNSS && conf.DNSServers == "" {
		return fmt.Errorf("list of dns servers is empty")
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
