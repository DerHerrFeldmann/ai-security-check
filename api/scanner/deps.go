package scanner

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

// DepVuln is a known vulnerability in a shipped dependency (Composer / npm).
type DepVuln struct {
	Package  string   `json:"package"`
	Version  string   `json:"version"`
	ID       string   `json:"id"`
	CVE      string   `json:"cve,omitempty"`
	Summary  string   `json:"summary"`
	Severity string   `json:"severity"`
	FixedIn  []string `json:"fixed_in,omitempty"`
}

type dep struct {
	name      string
	version   string
	ecosystem string
}

// scanDeps finds lockfiles under dir, collects all packages, and queries OSV.dev.
func scanDeps(dir string) []DepVuln {
	deps := gatherDeps(dir)
	if len(deps) == 0 {
		return []DepVuln{}
	}
	return queryOSV(deps)
}

func gatherDeps(dir string) []dep {
	seen := map[string]bool{}
	var deps []dep

	filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info == nil {
			return nil
		}
		if info.IsDir() {
			name := info.Name()
			if name == "node_modules" || name == ".git" {
				return filepath.SkipDir
			}
			return nil
		}
		switch info.Name() {
		case "composer.lock":
			deps = append(deps, parseComposerLock(path, seen)...)
		case "package-lock.json":
			deps = append(deps, parsePackageLock(path, seen)...)
		case "installed.json":
			if filepath.Base(filepath.Dir(path)) == "composer" {
				deps = append(deps, parseInstalledJSON(path, seen)...)
			}
		}
		return nil
	})

	return deps
}

func parseComposerLock(path string, seen map[string]bool) []dep {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var data struct {
		Packages []struct {
			Name    string `json:"name"`
			Version string `json:"version"`
		} `json:"packages"`
	}
	if err := json.Unmarshal(b, &data); err != nil {
		return nil
	}
	var deps []dep
	for _, p := range data.Packages {
		v := strings.TrimPrefix(p.Version, "v")
		key := "Packagist/" + p.Name + "@" + v
		if !seen[key] && p.Name != "" && v != "" {
			seen[key] = true
			deps = append(deps, dep{name: p.Name, version: v, ecosystem: "Packagist"})
		}
	}
	return deps
}

func parseInstalledJSON(path string, seen map[string]bool) []dep {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil
	}

	type pkg struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	}

	// Composer v2: {"packages": [...]}
	var wrapper struct {
		Packages []pkg `json:"packages"`
	}
	var packages []pkg
	if err := json.Unmarshal(b, &wrapper); err == nil && len(wrapper.Packages) > 0 {
		packages = wrapper.Packages
	} else {
		// Composer v1: flat array
		json.Unmarshal(b, &packages) //nolint:errcheck
	}

	var deps []dep
	for _, p := range packages {
		v := strings.TrimPrefix(p.Version, "v")
		key := "Packagist/" + p.Name + "@" + v
		if !seen[key] && p.Name != "" && v != "" {
			seen[key] = true
			deps = append(deps, dep{name: p.Name, version: v, ecosystem: "Packagist"})
		}
	}
	return deps
}

func parsePackageLock(path string, seen map[string]bool) []dep {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var raw struct {
		Packages map[string]struct {
			Version string `json:"version"`
		} `json:"packages"`
		Dependencies map[string]struct {
			Version string `json:"version"`
		} `json:"dependencies"`
	}
	if err := json.Unmarshal(b, &raw); err != nil {
		return nil
	}

	var deps []dep

	// npm v2/v3: "packages" map (keys are "node_modules/name")
	for key, pkg := range raw.Packages {
		if key == "" || pkg.Version == "" {
			continue
		}
		name := strings.TrimPrefix(key, "node_modules/")
		k := "npm/" + name + "@" + pkg.Version
		if !seen[k] {
			seen[k] = true
			deps = append(deps, dep{name: name, version: pkg.Version, ecosystem: "npm"})
		}
	}

	// npm v1: "dependencies" map (fallback)
	if len(deps) == 0 {
		for name, pkg := range raw.Dependencies {
			if pkg.Version == "" {
				continue
			}
			k := "npm/" + name + "@" + pkg.Version
			if !seen[k] {
				seen[k] = true
				deps = append(deps, dep{name: name, version: pkg.Version, ecosystem: "npm"})
			}
		}
	}

	return deps
}

func queryOSV(deps []dep) []DepVuln {
	type query struct {
		Package struct {
			Name      string `json:"name"`
			Ecosystem string `json:"ecosystem"`
		} `json:"package"`
		Version string `json:"version"`
	}

	queries := make([]query, len(deps))
	for i, d := range deps {
		queries[i].Package.Name = d.name
		queries[i].Package.Ecosystem = d.ecosystem
		queries[i].Version = d.version
	}

	body, err := json.Marshal(map[string]any{"queries": queries})
	if err != nil {
		return []DepVuln{}
	}

	resp, err := http.Post("https://api.osv.dev/v1/querybatch", "application/json", bytes.NewReader(body))
	if err != nil {
		return []DepVuln{}
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return []DepVuln{}
	}

	var batchResp struct {
		Results []struct {
			Vulns []struct {
				ID string `json:"id"`
			} `json:"vulns"`
		} `json:"results"`
	}
	if err := json.Unmarshal(raw, &batchResp); err != nil {
		return []DepVuln{}
	}

	// Collect unique IDs then hydrate
	vulnIDs := map[string]bool{}
	for _, r := range batchResp.Results {
		for _, v := range r.Vulns {
			if v.ID != "" {
				vulnIDs[v.ID] = true
			}
		}
	}

	details := map[string]*osvDetail{}
	for id := range vulnIDs {
		if d := getOSVDetail(id); d != nil {
			details[id] = d
		}
	}

	var findings []DepVuln
	for i, result := range batchResp.Results {
		if i >= len(deps) || len(result.Vulns) == 0 {
			continue
		}
		d := deps[i]
		for _, v := range result.Vulns {
			if detail, ok := details[v.ID]; ok {
				findings = append(findings, buildDepVuln(d, detail))
			}
		}
	}

	if findings == nil {
		return []DepVuln{}
	}
	return findings
}

type osvDetail struct {
	ID      string   `json:"id"`
	Aliases []string `json:"aliases"`
	Summary string   `json:"summary"`
	Affected []struct {
		Ranges []struct {
			Events []struct {
				Fixed string `json:"fixed"`
			} `json:"events"`
		} `json:"ranges"`
	} `json:"affected"`
	DatabaseSpecific struct {
		Severity string `json:"severity"`
	} `json:"database_specific"`
}

func getOSVDetail(id string) *osvDetail {
	resp, err := http.Get("https://api.osv.dev/v1/vulns/" + id)
	if err != nil || resp.StatusCode != 200 {
		return nil
	}
	defer resp.Body.Close()
	var d osvDetail
	if err := json.NewDecoder(resp.Body).Decode(&d); err != nil {
		return nil
	}
	return &d
}

func buildDepVuln(d dep, v *osvDetail) DepVuln {
	var cve string
	for _, a := range v.Aliases {
		if strings.HasPrefix(a, "CVE-") {
			cve = a
			break
		}
	}

	seen := map[string]bool{}
	var fixedIn []string
	for _, affected := range v.Affected {
		for _, r := range affected.Ranges {
			for _, e := range r.Events {
				if e.Fixed != "" && !seen[e.Fixed] {
					seen[e.Fixed] = true
					fixedIn = append(fixedIn, e.Fixed)
				}
			}
		}
	}

	severity := strings.ToLower(v.DatabaseSpecific.Severity)
	if severity == "" {
		severity = "unknown"
	}

	return DepVuln{
		Package:  d.name,
		Version:  d.version,
		ID:       v.ID,
		CVE:      cve,
		Summary:  v.Summary,
		Severity: severity,
		FixedIn:  fixedIn,
	}
}
