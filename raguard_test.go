package ndpspoof

import (
	"net/netip"
	"slices"
	"testing"

	"github.com/shadowy-pycoder/mshark/layers"
	"github.com/shadowy-pycoder/mshark/network"
	"github.com/stretchr/testify/require"
)

func getRa(t *testing.T) *layers.ICMPv6RouterAdvertisement {
	t.Helper()
	ra := &layers.ICMPv6RouterAdvertisement{
		CurHopLimit:    255,
		Prf:            layers.ICMPv6RouterPreferenceHigh,
		RouterLifetime: 30,
		Options: []layers.ICMPv6Option{
			&layers.ICMPv6OptMTU{MTU: 1500},
			&layers.ICMPv6OptLinkLayerAddress{Direction: layers.LLASource, Addr: network.IPv6MulticastMAC},
		},
	}
	return ra
}

func TestCreatePacketFromQuery(t *testing.T) {
	t.Parallel()

	testcases := []struct {
		name     string
		query    string
		expected *layers.IPv6Packet
	}{
		{
			name:  "simple hop by hop header",
			query: "HF",
			expected: &layers.IPv6Packet{
				Version:          6,
				TrafficClass:     layers.NewTrafficClass(0),
				FlowLabel:        0,
				PayloadLength:    40,
				NextHeader:       layers.IPProtocolHOPOPT,
				UpperLayer:       layers.IPProtocolICMPv6,
				FinalDestination: network.IPv6MulticastAllNodes,
				HopLimit:         255,
				SrcIP:            netip.IPv6Unspecified(),
				DstIP:            network.IPv6MulticastAllNodes,
				ExtHeaders: []layers.IPv6ExtHeader{
					&layers.HopByHopExtHeader{
						NextHeader: layers.IPProtocolICMPv6,
					},
				},
				Payload: getRa(t).ToBytes(),
			},
		},
		{
			name:  "no pfh headers",
			query: "FSD154",
			expected: &layers.IPv6Packet{
				Version:          6,
				TrafficClass:     layers.NewTrafficClass(0),
				FlowLabel:        0,
				PayloadLength:    1280,
				NextHeader:       layers.IPProtocolRoute,
				UpperLayer:       layers.IPProtocolICMPv6,
				FinalDestination: network.IPv6MulticastAllNodes,
				HopLimit:         255,
				SrcIP:            netip.IPv6Unspecified(),
				DstIP:            network.IPv6MulticastAllNodes,
				ExtHeaders: []layers.IPv6ExtHeader{
					getHeader("S", layers.IPProtocolOpts),
					&layers.DestOptsExtHeader{NextHeader: layers.IPProtocolICMPv6, HdrExtLen: 154},
				},
				Payload: getRa(t).ToBytes(),
			},
		},
		{
			name:  "no afh headers",
			query: "H2DR2F",
			expected: &layers.IPv6Packet{
				Version:          6,
				TrafficClass:     layers.NewTrafficClass(0),
				FlowLabel:        0,
				PayloadLength:    104,
				NextHeader:       layers.IPProtocolHOPOPT,
				UpperLayer:       layers.IPProtocolICMPv6,
				FinalDestination: netip.MustParseAddr("2001:db8::1"),
				HopLimit:         255,
				SrcIP:            netip.IPv6Unspecified(),
				DstIP:            network.IPv6MulticastAllNodes,
				ExtHeaders: []layers.IPv6ExtHeader{
					&layers.HopByHopExtHeader{
						NextHeader: layers.IPProtocolHOPOPT,
					},
					&layers.HopByHopExtHeader{
						NextHeader: layers.IPProtocolOpts,
					},
					&layers.DestOptsExtHeader{NextHeader: layers.IPProtocolRoute, HdrExtLen: 0},
					getHeader("R", layers.IPProtocolRoute),
					getHeader("R", layers.IPProtocolICMPv6),
				},
				Payload: getRa(t).ToBytes(),
			},
		},
		{
			name:  "advanced",
			query: "H2DDRLL F3 D255D23SLLN",
			expected: &layers.IPv6Packet{
				Version:          6,
				TrafficClass:     layers.NewTrafficClass(0),
				FlowLabel:        0,
				PayloadLength:    2368,
				NextHeader:       layers.IPProtocolHOPOPT,
				UpperLayer:       layers.IPProtocolICMPv6,
				FinalDestination: netip.MustParseAddr("2001:db8::1"),
				HopLimit:         255,
				SrcIP:            netip.IPv6Unspecified(),
				DstIP:            network.IPv6MulticastAllNodes,
				ExtHeaders: []layers.IPv6ExtHeader{
					&layers.HopByHopExtHeader{
						NextHeader: layers.IPProtocolHOPOPT,
					},
					&layers.HopByHopExtHeader{
						NextHeader: layers.IPProtocolOpts,
					},
					&layers.DestOptsExtHeader{NextHeader: layers.IPProtocolOpts, HdrExtLen: 0},
					&layers.DestOptsExtHeader{NextHeader: layers.IPProtocolRoute, HdrExtLen: 0},
					getHeader("R", layers.IPProtocolFragment),
					getHeader("L", layers.IPProtocolFragment),
					getHeader("L", layers.IPProtocolOpts),
					&layers.DestOptsExtHeader{NextHeader: layers.IPProtocolOpts, HdrExtLen: 255},
					&layers.DestOptsExtHeader{NextHeader: layers.IPProtocolRoute, HdrExtLen: 23},
					getHeader("S", layers.IPProtocolFragment),
					getHeader("L", layers.IPProtocolFragment),
					getHeader("L", layers.IPProtocolNoNxt),
				},
				Payload: getRa(t).ToBytes(),
			},
		},
	}
	ra := getRa(t).ToBytes()
	for _, testcase := range testcases {
		t.Run(testcase.name, func(t *testing.T) {
			sq, err := splitQuery(testcase.query)
			require.NoError(t, err)
			pfhSeq, err := parseHeaderPartSeq(sq[0])
			require.NoError(t, err)
			require.NoError(t, err)
			afhSeq, err := parseHeaderPartSeq(sq[2])
			require.NoError(t, err)
			pfh, afh := populateHeaders(pfhSeq, afhSeq)
			icmpv6 := layers.ProtoICMPv6
			actual, err := layers.NewIPv6Packet(
				netip.IPv6Unspecified(),
				network.IPv6MulticastAllNodes,
				slices.Concat(pfh, afh),
				&icmpv6,
				ra,
			)
			require.NoError(t, err)
			require.Equal(t, actual, testcase.expected)
		})
	}
}

func TestCreatePacketFromQueryErr(t *testing.T) {
	t.Parallel()
	testcases := []struct {
		name   string
		query  string
		errMsg string
	}{
		{
			name:   "digits first",
			query:  "1HF",
			errMsg: "packet query must not start with digits",
		},
		{
			name:   "one fragment needed",
			query:  "HDR",
			errMsg: "packet query must contain at least one fragment",
		},
		{
			name:   "destination option size",
			query:  "HD256RF",
			errMsg: "destination options size should be within 0-255",
		},
		{
			name:   "unknown header",
			query:  "WF",
			errMsg: "`W` header is not supported",
		},
		{
			name:   "consecutive headers",
			query:  "H2H16F",
			errMsg: "number of consecutive headers (18) is greater than 16",
		},
		{
			name:   "consecutive headers by letters",
			query:  "H2RRRRRRRRRRRRRRRRRF",
			errMsg: "number of consecutive headers (17) is greater than 16",
		},
		{
			name:   "consecutive fragments",
			query:  "HDRF2F16",
			errMsg: "number of fragment headers (18) is greater than 16",
		},
		{
			name:   "consecutive fragments of zero",
			query:  "HDRF2F0",
			errMsg: "number of consecutive headers (0) is greater than 16 or equal to 0",
		},
		{
			name:   "non fragment",
			query:  "HFDRF",
			errMsg: "fragment contains non-fragment value: `D`",
		},
		{
			name:   "pfh size",
			query:  "HD255D255F",
			errMsg: "pfh size (4104) bigger than max size (1224)",
		},
		{
			name:   "big payload",
			query:  "HDRFD255D255D255D255D255D255D255D255D255D255D255D255D255D255D255D255D255D255D255D255D255D255D255D255D255D255D255D255D255D255D255D255",
			errMsg: "maximum payload length is 65535 bytes, got 65608",
		},
		{
			name:   "negative numbers",
			query:  "HD-17F",
			errMsg: "number of consecutive headers (17) is greater than 16 or equal to 0",
		},
	}
	ra := getRa(t)
	for _, testcase := range testcases {
		t.Run(testcase.name, func(t *testing.T) {
			_, err := newRAGuardPayload(testcase.query, netip.IPv6Unspecified(), ra)
			require.EqualError(t, err, testcase.errMsg)
		})
	}
}
