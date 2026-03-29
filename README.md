# NDP spoof

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-yellow.svg)](https://www.gnu.org/licenses/gpl-3.0)
[![Go Reference](https://pkg.go.dev/badge/github.com/shadowy-pycoder/ndpspoof.svg)](https://pkg.go.dev/github.com/shadowy-pycoder/ndpspoof)
![GitHub go.mod Go version](https://img.shields.io/github/go-mod/go-version/shadowy-pycoder/ndpspoof)
[![Go Report Card](https://goreportcard.com/badge/github.com/shadowy-pycoder/ndpspoof)](https://goreportcard.com/report/github.com/shadowy-pycoder/ndpspoof)
![GitHub Release](https://img.shields.io/github/v/release/shadowy-pycoder/ndpspoof)
![GitHub Downloads (all assets, all releases)](https://img.shields.io/github/downloads/shadowy-pycoder/ndpspoof/total)
![GitHub Downloads (all assets, latest release)](https://img.shields.io/github/downloads/shadowy-pycoder/ndpspoof/latest/total)

## Install

1. Arch Linux/CachyOS/EndeavourOS

```shell
yay -S nf
```

2. Other systems

```shell
CGO_ENABLED=0 go install -ldflags "-s -w" -trimpath github.com/shadowy-pycoder/ndpspoof/cmd/nf@latest
```

## Usage

```shell
nf - IPv6 NDP spoofing tool by shadowy-pycoder

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
  -auto        Automatically set kernel parameters (Linux/Android) and network settings
  -i           The name of the network interface. Example: eth0 (Default: default interface)
  -interval    Interval between sent packets (Default: 5s)

  NA spoofing:
  -na          Enable NA (neighbor advertisement) spoofing mode
  -t           Targets for NA spoofing. (Example: "fe80::3a1c:7bff:fe22:91a4,fe80::b6d2:4cff:fe9a:5f10")
  -f           Fullduplex mode (send messages to targets and router)
  -g           IPv6 address of custom gateway (Default: default gateway)

  RA spoofing:
  -ra          Enable RA (router advertisement) spoofing. It is enabled when no spoofing mode specified
  -p           IPv6 prefix for RA spoofing (Example: 2001:db8:7a31:4400::/64)
  -mtu         MTU value to send in RA packet (Default: interface value)
  -rlt         Router lifetime value
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
```

### Example lab to test this tool

![Test RA lab](resources/RA_test.png)

1. Kali machine with Host-only network vboxnet0
2. Mint machine with Host-only network vboxnet1
3. Cisco IOS on Linux (IOL) Layer 2 Advanced Enterprise K9, Version 17.16.01a (x86_64)

On Kali machine run:

```shell
nf -d -auto -ra -i eth0 -p 2001:db8:7a31:4400::/64
```

On Mint machine run:

```shell
ip -6 route
```

You should see Kali machine link local IP as a default gateway

To test RA Guard evasion, first setup the switch:

```shell
configure terminal
nd raguard policy HOST
exit
interface range ethernet 0/0-1
ipv6 nd raguard attach-policy HOST
```

Run:

```shell
nf -d -auto -ra -i eth0 -p 2001:db8:7a31:4400::/64 -E F2DSDS
```

### Usage as a library

See [https://github.com/shadowy-pycoder/go-http-proxy-to-socks](https://github.com/shadowy-pycoder/go-http-proxy-to-socks)
