# NDP spoof

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-yellow.svg)](https://www.gnu.org/licenses/gpl-3.0)
[![Go Reference](https://pkg.go.dev/badge/github.com/shadowy-pycoder/ndpspoof.svg)](https://pkg.go.dev/github.com/shadowy-pycoder/ndpspoof)
![GitHub go.mod Go version](https://img.shields.io/github/go-mod/go-version/shadowy-pycoder/ndpspoof)
[![Go Report Card](https://goreportcard.com/badge/github.com/shadowy-pycoder/ndpspoof)](https://goreportcard.com/report/github.com/shadowy-pycoder/ndpspoof)
![GitHub Release](https://img.shields.io/github/v/release/shadowy-pycoder/ndpspoof)
![GitHub Downloads (all assets, all releases)](https://img.shields.io/github/downloads/shadowy-pycoder/ndpspoof/total)
![GitHub Downloads (all assets, latest release)](https://img.shields.io/github/downloads/shadowy-pycoder/ndpspoof/latest/total)

## Install

```shell
CGO_ENABLED=0 go install -ldflags "-s -w" -trimpath github.com/shadowy-pycoder/ndpspoof/cmd/af@latest
```

## Usage

```shell
Usage of nf:
  -I    Display list of interfaces and exit.
  -d    Enable debug logging
  -dns-servers string
        Comma separated list of DNS servers for RDNSS mode. Example: "2001:4860:4860::8888,2606:4700:4700::1111"
  -f    Run NA spoofing in fullduplex mode
  -g string
        IPv6 address of custom gateway (Default: default gateway)
  -i string
        The name of the network interface. Example: eth0 (Default: default interface)
  -na
        Enable NA (neighbor advertisement) spoofing
  -nocolor
        Disable colored output
  -ra
        Enable RA (router advertisement) spoofing. It is enabled when no spoof mode specified)
  -rdnss
        Enable RDNSS spoofing. Enabling this option requires -dns-servers flag
  -rlt duration
        Router lifetime for RA spoofing (default 30s)
  -t string
        Targets for NA spoofing. Example: "fe80::3a1c:7bff:fe22:91a4,fe80::b6d2:4cff:fe9a:5f10"
  -v    Show version and build information
```

### Usage as a library

See [https://github.com/shadowy-pycoder/go-http-proxy-to-socks](https://github.com/shadowy-pycoder/go-http-proxy-to-socks)
