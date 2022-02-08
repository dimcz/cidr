package cidr

import (
	"net"
	"strings"

	"github.com/pkg/errors"
)

// Bigger than we need, not too big to worry about overflow
const big = 0xFFFFFF

// ParseCIDR parses s as a CIDR notation IP address and prefix length,
// like "192.0.2.0/24", "192.0.2/24", "192.0/24" or "2001:db8::/32"
//
// It returns the IP address and the network implied by the IP and
// prefix length.
// For example, ParseCIDR("192.0.2.1/24") returns the IP address
// 192.0.2.1 and the network 192.0.2.0/24.
func ParseCIDR(s string) (net.IP, *net.IPNet, error) {
	i := strings.IndexByte(s, '/')
	if i < 0 {
		return nil, nil, errors.New("no find valid CIDR segment")
	}
	addr, mask := s[:i], s[i+1:]
	i = strings.Count(addr, ".")
	if i > 0 && i < 3 {
		addr += strings.Repeat(".0", 3-i)
	}
	iplen := net.IPv4len
	ip := parseIPv4(addr)
	if ip == nil {
		iplen = net.IPv6len
		ip = parseIPv6(addr)
	}
	n, i, ok := dtoi(mask)
	if ip == nil || !ok || i != len(mask) || n < 0 || n > 8*iplen {
		return nil, nil, errors.New("no find valid CIDR segment")
	}
	m := net.CIDRMask(n, 8*iplen)
	return ip, &net.IPNet{IP: ip.Mask(m), Mask: m}, nil
}

// Parse IPv4 address (d.d.d.d).
func parseIPv4(s string) net.IP {
	var p [net.IPv4len]byte
	for i := 0; i < net.IPv4len; i++ {
		if len(s) == 0 {
			// Missing octets.
			return nil
		}
		if i > 0 {
			if s[0] != '.' {
				return nil
			}
			s = s[1:]
		}
		n, c, ok := dtoi(s)
		if !ok || n > 0xFF {
			return nil
		}
		if c > 1 && s[0] == '0' {
			// Reject non-zero components with leading zeroes.
			return nil
		}
		s = s[c:]
		p[i] = byte(n)
	}
	if len(s) != 0 {
		return nil
	}
	return net.IPv4(p[0], p[1], p[2], p[3])
}

// parseIPv6 parses s as a literal IPv6 address described in RFC 4291
// and RFC 5952.
func parseIPv6(s string) (ip net.IP) {
	ip = make(net.IP, net.IPv6len)
	ellipsis := -1 // position of ellipsis in ip

	// Might have leading ellipsis
	if len(s) >= 2 && s[0] == ':' && s[1] == ':' {
		ellipsis = 0
		s = s[2:]
		// Might be only ellipsis
		if len(s) == 0 {
			return ip
		}
	}

	// Loop, parsing hex numbers followed by colon.
	i := 0
	for i < net.IPv6len {
		// Hex number.
		n, c, ok := xtoi(s)
		if !ok || n > 0xFFFF {
			return nil
		}

		// If followed by dot, might be in trailing IPv4.
		if c < len(s) && s[c] == '.' {
			if ellipsis < 0 && i != net.IPv6len-net.IPv4len {
				// Not the right place.
				return nil
			}
			if i+net.IPv4len > net.IPv6len {
				// Not enough room.
				return nil
			}
			ip4 := parseIPv4(s)
			if ip4 == nil {
				return nil
			}
			ip[i] = ip4[12]
			ip[i+1] = ip4[13]
			ip[i+2] = ip4[14]
			ip[i+3] = ip4[15]
			s = ""
			i += net.IPv4len
			break
		}

		// Save this 16-bit chunk.
		ip[i] = byte(n >> 8)
		ip[i+1] = byte(n)
		i += 2

		// Stop at end of string.
		s = s[c:]
		if len(s) == 0 {
			break
		}

		// Otherwise must be followed by colon and more.
		if s[0] != ':' || len(s) == 1 {
			return nil
		}
		s = s[1:]

		// Look for ellipsis.
		if s[0] == ':' {
			if ellipsis >= 0 { // already have one
				return nil
			}
			ellipsis = i
			s = s[1:]
			if len(s) == 0 { // can be at end
				break
			}
		}
	}

	// Must have used entire string.
	if len(s) != 0 {
		return nil
	}

	// If didn't parse enough, expand ellipsis.
	if i < net.IPv6len {
		if ellipsis < 0 {
			return nil
		}
		n := net.IPv6len - i
		for j := i - 1; j >= ellipsis; j-- {
			ip[j+n] = ip[j]
		}
		for j := ellipsis + n - 1; j >= ellipsis; j-- {
			ip[j] = 0
		}
	} else if ellipsis >= 0 {
		// Ellipsis must represent at least one 0 group.
		return nil
	}
	return ip
}

// Decimal to integer.
// Returns number, characters consumed, success.
func dtoi(s string) (n int, i int, ok bool) {
	n = 0
	for i = 0; i < len(s) && '0' <= s[i] && s[i] <= '9'; i++ {
		n = n*10 + int(s[i]-'0')
		if n >= big {
			return big, i, false
		}
	}
	if i == 0 {
		return 0, 0, false
	}
	return n, i, true
}

// Hexadecimal to integer.
// Returns number, characters consumed, success.
func xtoi(s string) (n int, i int, ok bool) {
	n = 0
	for i = 0; i < len(s); i++ {
		if '0' <= s[i] && s[i] <= '9' {
			n *= 16
			n += int(s[i] - '0')
		} else if 'a' <= s[i] && s[i] <= 'f' {
			n *= 16
			n += int(s[i]-'a') + 10
		} else if 'A' <= s[i] && s[i] <= 'F' {
			n *= 16
			n += int(s[i]-'A') + 10
		} else {
			break
		}
		if n >= big {
			return 0, i, false
		}
	}
	if i == 0 {
		return 0, i, false
	}
	return n, i, true
}
