package apigateway

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strings"
)

var (
	domainRegex = regexp.MustCompile(`^(?i:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$`)

	privateIPv4Blocks = []*net.IPNet{
		parseCIDR("0.0.0.0/8"),          // RFC 1122 "This host on this network"
		parseCIDR("10.0.0.0/8"),         // RFC 1918 Private-Use
		parseCIDR("100.64.0.0/10"),      // RFC 6598 Shared Address Space / CGNAT (includes Alibaba metadata 100.100.100.200)
		parseCIDR("127.0.0.0/8"),        // RFC 1122 Loopback
		parseCIDR("169.254.0.0/16"),     // RFC 3927 Link-Local / Cloud Metadata (169.254.169.254, AWS/GCP/Azure/OCI)
		parseCIDR("172.16.0.0/12"),      // RFC 1918 Private-Use
		parseCIDR("192.0.0.0/24"),       // RFC 6890 IETF Protocol Assignments
		parseCIDR("192.0.2.0/24"),       // RFC 5737 Documentation (TEST-NET-1)
		parseCIDR("192.168.0.0/16"),     // RFC 1918 Private-Use
		parseCIDR("198.18.0.0/15"),      // RFC 2544 Benchmarking
		parseCIDR("198.51.100.0/24"),    // RFC 5737 Documentation (TEST-NET-2)
		parseCIDR("203.0.113.0/24"),     // RFC 5737 Documentation (TEST-NET-3)
		parseCIDR("224.0.0.0/4"),        // RFC 1112 Multicast
		parseCIDR("240.0.0.0/4"),        // RFC 1112 Reserved for Future Use
		parseCIDR("255.255.255.255/32"), // RFC 919 Limited Broadcast
	}

	privateIPv6Blocks = []*net.IPNet{
		parseCIDR("::/128"),        // RFC 4291 Unspecified Address
		parseCIDR("::1/128"),       // RFC 4291 Loopback
		parseCIDR("::ffff:0:0/96"), // RFC 4291 IPv4-mapped IPv6
		parseCIDR("64:ff9b::/96"),  // RFC 6052 IPv4/IPv6 translation
		parseCIDR("2001:db8::/32"), // RFC 3849 Documentation
		parseCIDR("fc00::/7"),      // RFC 4193 Unique Local Address (ULA)
		parseCIDR("fe80::/10"),     // RFC 4291 Link-Local Unicast
		parseCIDR("ff00::/8"),      // RFC 4291 Multicast
	}
)

func isCloudMetadataHost(host string) bool {
	h := strings.ToLower(strings.TrimSpace(host))
	return h == "169.254.169.254" ||
		h == "100.100.100.200" ||
		h == "169.254.169.250" ||
		h == "metadata.google.internal" ||
		h == "instance-data" ||
		h == "metadata.tencentyun.com" ||
		h == "metadata.aliyun.com" ||
		strings.HasSuffix(h, ".internal") ||
		strings.HasSuffix(h, ".local")
}

func parseCIDR(s string) *net.IPNet {
	_, block, err := net.ParseCIDR(s)
	if err != nil {
		panic(fmt.Sprintf("invalid static CIDR %s: %v", s, err))
	}
	return block
}

// ValidateSafeTargetURL validates an outbound destination URL against SSRF attacks.
// It rejects loopback, private RFC 1918 networks, link-local metadata addresses, and cloud provider hypervisor IPs.
func ValidateSafeTargetURL(rawURL string) error {
	u, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("invalid URL: %w", err)
	}

	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return fmt.Errorf("unsupported URL scheme '%s': only http and https are permitted", scheme)
	}

	hostname := u.Hostname()
	if hostname == "" {
		return errors.New("missing hostname in target URL")
	}

	// In development mode, allow localhost for mock servers (strictly overridden by production mode)
	isDev := IsDevelopmentEnv()
	if isDev && (hostname == "127.0.0.1" || hostname == "localhost" || strings.HasPrefix(hostname, "127.")) {
		return nil
	}

	// Reject cloud metadata hostnames and IPs outright
	if isCloudMetadataHost(hostname) {
		return fmt.Errorf("access to cloud provider instance metadata (%s) is prohibited", hostname)
	}

	// Resolve IP addresses
	ips, err := net.LookupIP(hostname)
	if err != nil {
		// If DNS resolution fails, check if hostname is direct IP
		ip := net.ParseIP(hostname)
		if ip == nil {
			return fmt.Errorf("could not resolve hostname '%s': %w", hostname, err)
		}
		ips = []net.IP{ip}
	}

	for _, ip := range ips {
		if isPrivateIP(ip) && !isDev {
			return fmt.Errorf("target host '%s' resolves to prohibited private or loopback IP (%s)", hostname, ip.String())
		}
	}

	return nil
}

// ValidateSafeUpstreamURL validates an upstream backend target URL before creating a proxy pool.
// It verifies safe scheme (http/https), valid hostname, and unconditionally blocks cloud metadata endpoints.
func ValidateSafeUpstreamURL(rawURL string) error {
	u, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("invalid upstream URL: %w", err)
	}

	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return fmt.Errorf("unsupported upstream URL scheme '%s': only http and https are permitted", scheme)
	}

	hostname := u.Hostname()
	if hostname == "" {
		return errors.New("missing hostname in upstream URL")
	}

	// Unconditionally reject cloud metadata endpoints in all environments
	if isCloudMetadataHost(hostname) {
		return fmt.Errorf("upstream URL targeting cloud provider instance metadata (%s) is prohibited", hostname)
	}

	// In production, validate safe target URL (reject unapproved destination ranges)
	if IsProductionEnv() {
		return ValidateSafeTargetURL(rawURL)
	}

	return nil
}

func isPrivateIP(ip net.IP) bool {
	if ip == nil {
		return true
	}
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() || ip.IsMulticast() {
		return true
	}

	if ip4 := ip.To4(); ip4 != nil {
		for _, block := range privateIPv4Blocks {
			if block.Contains(ip4) {
				return true
			}
		}
		return false
	}

	for _, block := range privateIPv6Blocks {
		if block.Contains(ip) {
			return true
		}
	}

	return false
}

// ValidateDomainName verifies that a given domain string follows valid DNS syntax.
func ValidateDomainName(domain string) error {
	domain = strings.TrimSpace(domain)
	if domain == "" {
		return errors.New("domain name cannot be empty")
	}
	if len(domain) > 253 {
		return errors.New("domain name exceeds maximum length of 253 characters")
	}
	if !domainRegex.MatchString(domain) {
		return fmt.Errorf("domain '%s' has invalid syntax", domain)
	}
	return nil
}

// SanitizeHeaderValue strips control characters (newlines, carriage returns) to prevent HTTP response splitting.
func SanitizeHeaderValue(val string) string {
	val = strings.ReplaceAll(val, "\r", "")
	val = strings.ReplaceAll(val, "\n", "")
	return strings.TrimSpace(val)
}
