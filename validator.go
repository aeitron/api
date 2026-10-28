package apigateway

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"regexp"
	"strings"
)

var (
	domainRegex = regexp.MustCompile(`^(?i:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$`)

	privateIPv4Blocks = []*net.IPNet{
		parseCIDR("10.0.0.0/8"),
		parseCIDR("172.16.0.0/12"),
		parseCIDR("192.168.0.0/16"),
		parseCIDR("127.0.0.0/8"),
		parseCIDR("169.254.0.0/16"), // Link-local / Cloud metadata (169.254.169.254)
		parseCIDR("0.0.0.0/8"),
		parseCIDR("224.0.0.0/4"), // Multicast
		parseCIDR("240.0.0.0/4"), // Reserved
	}

	privateIPv6Blocks = []*net.IPNet{
		parseCIDR("::1/128"),
		parseCIDR("fc00::/7"),  // Unique local address
		parseCIDR("fe80::/10"), // Link-local
	}
)

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

	// Reject raw cloud metadata IP outright
	if hostname == "169.254.169.254" || hostname == "metadata.google.internal" || hostname == "instance-data" {
		return errors.New("access to cloud provider instance metadata is prohibited")
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
// It verifies safe scheme (http/https), valid hostname, and unconditionally blocks cloud metadata endpoints (169.254.169.254, metadata.google.internal).
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
	if hostname == "169.254.169.254" || hostname == "metadata.google.internal" || hostname == "instance-data" {
		return errors.New("upstream URL targeting cloud provider instance metadata is prohibited")
	}

	// In production, validate safe target URL (reject unapproved destination ranges)
	isProd := strings.EqualFold(os.Getenv("AEITRON_ENV"), "production") || strings.EqualFold(os.Getenv("AEITRON_DEV_MODE"), "false")
	if isProd {
		return ValidateSafeTargetURL(rawURL)
	}

	return nil
}

func isPrivateIP(ip net.IP) bool {
	if ip == nil {
		return true
	}
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() {
		return true
	}

	if ip4 := ip.To4(); ip4 != nil {
		for _, block := range privateIPv4Blocks {
			if block.Contains(ip4) {
				return true
			}
		}
	} else {
		for _, block := range privateIPv6Blocks {
			if block.Contains(ip) {
				return true
			}
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
