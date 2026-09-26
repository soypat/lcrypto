package x509

// VerifyHostname returns nil if c is valid for host, following crypto/x509's
// Certificate.VerifyHostname: IP literals, optionally in square brackets, are
// matched against IP address names; other names case-insensitively against DNS
// names, where a valid pattern may have a wildcard as its complete left-most
// label. The legacy Common Name is ignored.
func (c *Certificate) VerifyHostname(host []byte) error {
	candidateIP := host
	if len(host) >= 3 && host[0] == '[' && host[len(host)-1] == ']' {
		candidateIP = host[1 : len(host)-1]
	}
	var it sanIter
	if ip, ok := parseIP(candidateIP); ok {
		it.init(c.SubjectAltName)
		for tag, data, ok := it.next(); ok; tag, data, ok = it.next() {
			if tag == nameTypeIP && ipEqual(ip[:], data) {
				return nil
			}
		}
		return ErrHostname
	}
	validCandidate := validHostname(host, false)
	it.init(c.SubjectAltName)
	for tag, match, ok := it.next(); ok; tag, match, ok = it.next() {
		if tag != nameTypeDNS {
			continue
		}
		if validCandidate && validHostname(match, true) {
			if matchHostnames(match, host) {
				return nil
			}
		} else if matchExactly(match, host) {
			return nil
		}
	}
	return ErrHostname
}

// ipEqual is net.IP.Equal of a 16 byte address and a 4 or 16 byte one.
func ipEqual(ip16 []byte, other []byte) bool {
	if len(other) == 4 {
		return isV4Mapped(ip16) && string(ip16[12:]) == string(other)
	}
	return string(ip16) == string(other)
}

func lower(c byte) byte {
	if 'A' <= c && c <= 'Z' {
		c += 'a' - 'A'
	}
	return c
}

func equalFold(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if lower(a[i]) != lower(b[i]) {
			return false
		}
	}
	return true
}

func trimDot(s []byte) []byte {
	if len(s) > 0 && s[len(s)-1] == '.' {
		return s[:len(s)-1]
	}
	return s
}

// nextLabel splits s at its first '.'.
func nextLabel(s []byte) (label, rest []byte, more bool) {
	for i, c := range s {
		if c == '.' {
			return s[:i], s[i+1:], true
		}
	}
	return s, nil, false
}

// validHostname reports whether host is a valid hostname that can be matched
// or matched against according to RFC 6125 2.2, as crypto/x509's.
func validHostname(host []byte, isPattern bool) bool {
	if !isPattern {
		host = trimDot(host)
	}
	if len(host) == 0 || string(host) == "*" {
		return false
	}
	for i, more := 0, true; more; i++ {
		var part []byte
		part, host, more = nextLabel(host)
		if len(part) == 0 {
			return false
		}
		if isPattern && i == 0 && string(part) == "*" {
			continue
		}
		for j, c := range part {
			if 'a' <= c && c <= 'z' || '0' <= c && c <= '9' || 'A' <= c && c <= 'Z' ||
				c == '-' && j != 0 || c == '_' {
				continue
			}
			return false
		}
	}
	return true
}

func matchExactly(a, b []byte) bool {
	if len(a) == 0 || string(a) == "." || len(b) == 0 || string(b) == "." {
		return false
	}
	return equalFold(a, b)
}

// matchHostnames matches pattern against host, which has a trailing dot
// removed, label by label with a wildcard allowed as the first pattern label.
func matchHostnames(pattern, host []byte) bool {
	host = trimDot(host)
	if len(pattern) == 0 {
		return false
	}
	pmore, hmore := true, true
	for i := 0; pmore && hmore; i++ {
		var p, h []byte
		p, pattern, pmore = nextLabel(pattern)
		h, host, hmore = nextLabel(host)
		if i == 0 && string(p) == "*" {
			continue
		}
		if !equalFold(p, h) {
			return false
		}
	}
	return pmore == hmore // Same number of labels.
}

// parseIP is netip.ParseAddr returning the address in 16 byte form; IPv4
// addresses are IPv4-mapped. IPv6 zones are accepted and dropped.
func parseIP(s []byte) (ip [16]byte, ok bool) {
	// Call before returning ip: Go does not order reading ip in the return
	// statement against the call writing it, and TinyGo reads it first.
	for _, c := range s {
		switch c {
		case '.':
			ip[10], ip[11] = 0xff, 0xff
			ok = parseIPv4(s, ip[12:])
			return ip, ok
		case ':':
			ok = parseIPv6(s, &ip)
			return ip, ok
		case '%':
			return ip, false
		}
	}
	return ip, false
}

// parseIPv4 is netip's parseIPv4Fields.
func parseIPv4(s []byte, fields []byte) bool {
	var val, pos, digLen int
	for i, c := range s {
		switch {
		case '0' <= c && c <= '9':
			if digLen == 1 && val == 0 {
				return false // Leading zero.
			}
			val = val*10 + int(c-'0')
			digLen++
			if val > 255 {
				return false
			}
		case c == '.':
			if i == 0 || i == len(s)-1 || s[i-1] == '.' || pos == 3 {
				return false
			}
			fields[pos] = byte(val)
			pos++
			val, digLen = 0, 0
		default:
			return false
		}
	}
	if pos < 3 {
		return false
	}
	fields[3] = byte(val)
	return true
}

// parseIPv6 is netip's parseIPv6.
func parseIPv6(s []byte, ip *[16]byte) bool {
	for i, c := range s {
		if c == '%' {
			if i == len(s)-1 {
				return false // Empty zone.
			}
			s = s[:i]
			break
		}
	}
	ellipsis := -1
	if len(s) >= 2 && s[0] == ':' && s[1] == ':' {
		ellipsis = 0
		s = s[2:]
		if len(s) == 0 {
			return true
		}
	}
	i := 0
	for i < 16 {
		off := 0
		acc := uint32(0)
		for ; off < len(s); off++ {
			c := s[off]
			switch {
			case '0' <= c && c <= '9':
				acc = acc<<4 + uint32(c-'0')
			case 'a' <= c && c <= 'f':
				acc = acc<<4 + uint32(c-'a'+10)
			case 'A' <= c && c <= 'F':
				acc = acc<<4 + uint32(c-'A'+10)
			default:
				goto end
			}
			if off > 3 || acc > 0xffff {
				return false
			}
		}
	end:
		if off == 0 {
			return false
		}
		if off < len(s) && s[off] == '.' {
			if ellipsis < 0 && i != 12 || i+4 > 16 || !parseIPv4(s, ip[i:i+4]) {
				return false
			}
			s = nil
			i += 4
			break
		}
		ip[i], ip[i+1] = byte(acc>>8), byte(acc)
		i += 2
		s = s[off:]
		if len(s) == 0 {
			break
		}
		if s[0] != ':' || len(s) == 1 {
			return false
		}
		s = s[1:]
		if s[0] == ':' {
			if ellipsis >= 0 {
				return false
			}
			ellipsis = i
			s = s[1:]
			if len(s) == 0 {
				break
			}
		}
	}
	if len(s) != 0 {
		return false
	}
	if i < 16 {
		if ellipsis < 0 {
			return false
		}
		n := 16 - i
		for j := i - 1; j >= ellipsis; j-- {
			ip[j+n] = ip[j]
		}
		clear(ip[ellipsis : ellipsis+n])
	} else if ellipsis >= 0 {
		return false
	}
	return true
}
