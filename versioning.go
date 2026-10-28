package apigateway

import (
	"fmt"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

// Header names conforming to Stripe-grade date-based API evolution
const (
	HeaderAeitronVersion   = "Aeitron-Version"
	HeaderXAeitronVersion  = "X-Aeitron-Version"
	HeaderAPIVersion       = "API-Version"
	HeaderXDeprecationDate = "X-Aeitron-Deprecation-Date"
	HeaderSunset           = "Sunset"
	HeaderLink             = "Link"
	HeaderWarning          = "X-Aeitron-Warning"
	DefaultBaselineVersion = "2026-11-01"
	VersioningDocsURL      = "https://docs.aeitron.com/api/versioning"
)

var versionDateRegex = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}$`)

// APIVersion defines the operational lifecycle and evolution metadata for a dated API contract.
type APIVersion struct {
	Version         string    `json:"version"`          // e.g. "2026-11-01"
	ReleaseDate     time.Time `json:"release_date"`     // Date the version became generally available
	IsBaseline      bool      `json:"is_baseline"`      // Whether this is the default server-authoritative baseline
	IsDeprecated    bool      `json:"is_deprecated"`    // Whether this version is marked for deprecation
	DeprecationDate time.Time `json:"deprecation_date"` // Date deprecation was formally announced
	SunsetDate      time.Time `json:"sunset_date"`      // Strict RFC 8594 decommission date
	MigrationGuide  string    `json:"migration_guide"`  // Canonical URL for client migration documentation
}

// VersionTransformer allows bidirectional request/response payload adaptation for backwards compatibility.
type VersionTransformer interface {
	TransformRequest(path string, body []byte) ([]byte, error)
	TransformResponse(path string, statusCode int, body []byte) ([]byte, error)
}

// VersioningPolicy manages date-based version negotiation, lifecycle validation, and deprecation telemetry.
type VersioningPolicy struct {
	mu              sync.RWMutex
	versions        map[string]APIVersion
	baselineVersion string
	transformers    map[string]VersionTransformer
}

// NewVersioningPolicy initializes the canonical Aeitron API evolution policy.
func NewVersioningPolicy() *VersioningPolicy {
	vp := &VersioningPolicy{
		versions:        make(map[string]APIVersion),
		baselineVersion: DefaultBaselineVersion,
		transformers:    make(map[string]VersionTransformer),
	}

	// 1. Current Production Standard Baseline (Latest)
	vp.RegisterVersion(APIVersion{
		Version:     "2026-11-01",
		ReleaseDate: time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC),
		IsBaseline:  true,
	})

	// 2. Active Maintenance Version
	vp.RegisterVersion(APIVersion{
		Version:     "2026-06-01",
		ReleaseDate: time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC),
		IsBaseline:  false,
	})

	// 3. Deprecated Legacy Version (Scheduled for Sunset on 2027-01-01)
	vp.RegisterVersion(APIVersion{
		Version:         "2026-01-01",
		ReleaseDate:     time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		IsBaseline:      false,
		IsDeprecated:    true,
		DeprecationDate: time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC),
		SunsetDate:      time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC),
		MigrationGuide:  VersioningDocsURL + "/migration-2026-01-01-to-2026-11-01",
	})

	return vp
}

// RegisterVersion adds or updates a supported API version.
func (vp *VersioningPolicy) RegisterVersion(v APIVersion) {
	vp.mu.Lock()
	defer vp.mu.Unlock()
	vp.versions[v.Version] = v
	if v.IsBaseline {
		vp.baselineVersion = v.Version
	}
}

// BaselineVersion returns the current default baseline version.
func (vp *VersioningPolicy) BaselineVersion() string {
	vp.mu.RLock()
	defer vp.mu.RUnlock()
	return vp.baselineVersion
}

// SupportedVersions returns a sorted list of all registered API versions.
func (vp *VersioningPolicy) SupportedVersions() []string {
	vp.mu.RLock()
	defer vp.mu.RUnlock()
	var list []string
	for k := range vp.versions {
		list = append(list, k)
	}
	sort.Strings(list)
	return list
}

// RegisterTransformer binds a compatibility transformer for a specific version.
func (vp *VersioningPolicy) RegisterTransformer(version string, t VersionTransformer) {
	vp.mu.Lock()
	defer vp.mu.Unlock()
	vp.transformers[version] = t
}

// Transformer returns the compatibility transformer for a version, if registered.
func (vp *VersioningPolicy) Transformer(version string) VersionTransformer {
	vp.mu.RLock()
	defer vp.mu.RUnlock()
	return vp.transformers[version]
}

// Negotiate extracts, validates, and resolves the effective API version for an incoming HTTP request.
// If the version header is omitted, it defaults to the configured baseline version.
// If an invalid format or unsupported version is requested, an error is returned.
func (vp *VersioningPolicy) Negotiate(r *http.Request) (string, *APIVersion, error) {
	// 1. Extract version from Aeitron-Version, X-Aeitron-Version, or API-Version
	candidate := strings.TrimSpace(r.Header.Get(HeaderAeitronVersion))
	if candidate == "" {
		candidate = strings.TrimSpace(r.Header.Get(HeaderXAeitronVersion))
	}
	if candidate == "" {
		candidate = strings.TrimSpace(r.Header.Get(HeaderAPIVersion))
	}

	vp.mu.RLock()
	defer vp.mu.RUnlock()

	// 2. Default to baseline if header is omitted
	if candidate == "" {
		baseline := vp.versions[vp.baselineVersion]
		return vp.baselineVersion, &baseline, nil
	}

	// 3. Validate calendar date format (YYYY-MM-DD)
	if !versionDateRegex.MatchString(candidate) {
		return "", nil, fmt.Errorf("malformed API version '%s': must be formatted as YYYY-MM-DD", candidate)
	}

	// 4. Validate that version exists in the supported registry
	v, exists := vp.versions[candidate]
	if !exists {
		return "", nil, fmt.Errorf("unsupported API version '%s': supported versions are [%s]", candidate, strings.Join(vp.SupportedVersions(), ", "))
	}

	return candidate, &v, nil
}

func addVaryHeader(w http.ResponseWriter, field string) {
	existing := w.Header().Get("Vary")
	if existing == "" {
		w.Header().Set("Vary", field)
	} else if !strings.Contains(existing, field) {
		w.Header().Set("Vary", existing+", "+field)
	}
}

// ApplyHeaders injects Stripe-style evolution and RFC 8594 sunset/deprecation headers into the downstream response.
func (vp *VersioningPolicy) ApplyHeaders(w http.ResponseWriter, version string, vInfo *APIVersion) {
	// Downstream contract identification
	w.Header().Set(HeaderAeitronVersion, version)
	addVaryHeader(w, HeaderAeitronVersion)

	if vInfo != nil && vInfo.IsDeprecated {
		// RFC 8594 / Stripe Deprecation Headers
		sunsetHTTPDate := vInfo.SunsetDate.Format(http.TimeFormat)
		depDateStr := vInfo.SunsetDate.Format("2006-01-02")
		if !vInfo.DeprecationDate.IsZero() {
			depDateStr = vInfo.SunsetDate.Format("2006-01-02")
		}

		w.Header().Set(HeaderXDeprecationDate, depDateStr)
		w.Header().Set(HeaderSunset, sunsetHTTPDate)

		link := fmt.Sprintf("<%s>; rel=\"deprecation\"", VersioningDocsURL)
		if vInfo.MigrationGuide != "" {
			link = fmt.Sprintf("<%s>; rel=\"deprecation\", <%s>; rel=\"migration\"", VersioningDocsURL, vInfo.MigrationGuide)
		}
		w.Header().Set(HeaderLink, link)

		warningMsg := fmt.Sprintf(`299 aeitron "API version '%s' is deprecated and scheduled for sunset on %s. Please upgrade to '%s'."`,
			version, depDateStr, vp.BaselineVersion())
		w.Header().Set(HeaderWarning, warningMsg)
	}
}
