package scanner

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
)

// CVEFinding is a known vulnerability from wpvulnerability.net affecting the installed version.
type CVEFinding struct {
	UUID         string   `json:"uuid"`
	Title        string   `json:"title"`
	CVSSScore    float64  `json:"cvss_score"`
	CVSSSeverity string   `json:"cvss_severity,omitempty"`
	FixedIn      string   `json:"fixed_in,omitempty"`
	Unfixed      bool     `json:"unfixed"`
	References   []string `json:"references,omitempty"`
}

// fetchCVEs queries wpvulnerability.net for known CVEs and filters them to those
// that affect the given installed version. Returns an empty slice on any error.
func fetchCVEs(slug, version string) []CVEFinding {
	resp, err := http.Get(fmt.Sprintf("https://www.wpvulnerability.net/plugin/%s", slug))
	if err != nil || resp.StatusCode != 200 {
		return []CVEFinding{}
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return []CVEFinding{}
	}

	var apiResp struct {
		Data struct {
			Vulnerability []struct {
				UUID     string `json:"uuid"`
				Name     string `json:"name"`
				Operator struct {
					MaxVersion  string `json:"max_version"`
					MaxOperator string `json:"max_operator"`
					Unfixed     string `json:"unfixed"`
				} `json:"operator"`
				Impact struct {
					CVSS struct {
						Score    float64 `json:"score"`
						Severity string  `json:"severity"`
					} `json:"cvss"`
				} `json:"impact"`
				Source []struct {
					Name string `json:"name"`
					Link string `json:"link"`
				} `json:"source"`
			} `json:"vulnerability"`
		} `json:"data"`
	}

	if err := json.Unmarshal(body, &apiResp); err != nil {
		return []CVEFinding{}
	}

	var findings []CVEFinding
	for _, v := range apiResp.Data.Vulnerability {
		op := v.Operator
		unfixed := op.Unfixed == "1" || op.Unfixed == "true"
		if !cveApplies(op.MaxVersion, op.MaxOperator, unfixed, version) {
			continue
		}

		var refs []string
		for _, s := range v.Source {
			if s.Link != "" {
				refs = append(refs, s.Link)
			}
		}

		findings = append(findings, CVEFinding{
			UUID:         v.UUID,
			Title:        v.Name,
			CVSSScore:    v.Impact.CVSS.Score,
			CVSSSeverity: strings.ToLower(v.Impact.CVSS.Severity),
			FixedIn:      op.MaxVersion,
			Unfixed:      unfixed,
			References:   refs,
		})
	}

	if findings == nil {
		return []CVEFinding{}
	}
	return findings
}

// cveApplies returns true when the installed version falls within the affected range.
func cveApplies(maxVersion, maxOp string, unfixed bool, installed string) bool {
	if unfixed {
		return true
	}
	if installed == "" || maxVersion == "" {
		return false
	}
	cmp := compareVersions(installed, maxVersion)
	if maxOp == "<=" {
		return cmp <= 0
	}
	return cmp < 0 // default operator is "<"
}

// compareVersions compares two dot-separated version strings numerically.
// Returns -1 if a < b, 0 if equal, 1 if a > b.
func compareVersions(a, b string) int {
	a = strings.TrimPrefix(a, "v")
	b = strings.TrimPrefix(b, "v")

	partsA := strings.Split(a, ".")
	partsB := strings.Split(b, ".")

	n := len(partsA)
	if len(partsB) > n {
		n = len(partsB)
	}

	for i := 0; i < n; i++ {
		var na, nb int
		if i < len(partsA) {
			na, _ = strconv.Atoi(partsA[i])
		}
		if i < len(partsB) {
			nb, _ = strconv.Atoi(partsB[i])
		}
		if na < nb {
			return -1
		}
		if na > nb {
			return 1
		}
	}
	return 0
}
