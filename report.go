package main

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"encoding/xml"
	"fmt"
	htmltemplate "html/template"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"text/template"
	"time"
)

//go:embed summary-template.html
var summaryTemplateContent string

// ---------------------------------------------------------------------------
// Trivy JSON report — only the fields read by the templates and the summary
// ---------------------------------------------------------------------------

// Vulnerability is embedded in detectedVuln so the JSON stays flat while the
// detail template can use both .Severity and .Vulnerability.Severity, exactly
// like trivy's own types.
type Vulnerability struct {
	Title       string
	Description string
	Severity    string
	References  []string
}

type detectedVuln struct {
	VulnerabilityID  string
	PkgName          string
	InstalledVersion string
	FixedVersion     string
	PkgPath          string
	PrimaryURL       string
	Vulnerability
}

type misconfiguration struct {
	Type       string
	ID         string
	Title      string
	Message    string
	Severity   string
	Status     string
	PrimaryURL string
}

type result struct {
	Target            string
	Class             string
	Type              string
	Vulnerabilities   []detectedVuln
	Misconfigurations []misconfiguration
}

type trivyReport struct {
	ArtifactName string
	Metadata     struct {
		OS *struct {
			Family string
			Name   string
		}
		RepoTags []string
		ImageID  string
	}
	Results []result
}

func loadReport(path string) (*trivyReport, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var rep trivyReport
	if err := json.NewDecoder(f).Decode(&rep); err != nil {
		return nil, fmt.Errorf("decode %s: %w", path, err)
	}
	return &rep, nil
}

// ---------------------------------------------------------------------------
// Severity filter (-s), applied at render time
// ---------------------------------------------------------------------------

// severitySet is the set of severities to display; nil means all.
type severitySet map[string]bool

func parseSeverity(s string) severitySet {
	set := severitySet{}
	for _, p := range strings.Split(s, ",") {
		if p = strings.ToUpper(strings.TrimSpace(p)); p != "" {
			set[p] = true
		}
	}
	if len(set) == 0 {
		return nil
	}
	return set
}

func (s severitySet) has(sev string) bool {
	return s == nil || s[strings.ToUpper(sev)]
}

// severityRank orders severities like trivy: CRITICAL first, unknown values last.
var severityRank = map[string]int{"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}

// filterResults mirrors what trivy does before rendering a report:
// drop findings outside the severity set and misconfigurations that did not
// fail, dedupe vulnerabilities and sort them in trivy's order.
func filterResults(results []result, sev severitySet) []result {
	if results == nil {
		return nil
	}
	out := make([]result, 0, len(results))
	for _, r := range results {
		fr := r
		fr.Vulnerabilities = nil
		seen := map[[4]string]bool{}
		for _, v := range r.Vulnerabilities {
			key := [4]string{v.VulnerabilityID, v.PkgName, v.InstalledVersion, v.PkgPath}
			if sev.has(v.Severity) && !seen[key] {
				seen[key] = true
				fr.Vulnerabilities = append(fr.Vulnerabilities, v)
			}
		}
		sort.SliceStable(fr.Vulnerabilities, func(i, j int) bool {
			a, b := fr.Vulnerabilities[i], fr.Vulnerabilities[j]
			if a.PkgName != b.PkgName {
				return a.PkgName < b.PkgName
			}
			if a.InstalledVersion != b.InstalledVersion {
				return a.InstalledVersion < b.InstalledVersion
			}
			if ra, rb := severityRank[strings.ToUpper(a.Severity)], severityRank[strings.ToUpper(b.Severity)]; ra != rb {
				return ra > rb
			}
			if a.VulnerabilityID != b.VulnerabilityID {
				return a.VulnerabilityID < b.VulnerabilityID
			}
			return a.PkgPath < b.PkgPath
		})
		fr.Misconfigurations = nil
		for _, m := range r.Misconfigurations {
			if m.Status == "FAIL" && sev.has(m.Severity) {
				fr.Misconfigurations = append(fr.Misconfigurations, m)
			}
		}
		out = append(out, fr)
	}
	return out
}

// ---------------------------------------------------------------------------
// Detail page — trivy-template.html rendered in Go (replaces trivy convert)
// ---------------------------------------------------------------------------

// detailTmpl uses text/template on purpose: every field in the template goes
// through escapeXML, and html/template would re-escape it and rewrite the JS.
var detailTmpl = template.Must(template.New("detail").Funcs(template.FuncMap{
	"escapeXML": func(s string) string {
		var b bytes.Buffer
		_ = xml.EscapeText(&b, []byte(s))
		return b.String()
	},
	"toString": func(v any) string { return fmt.Sprint(v) },
	"now":      time.Now,
	"date":     func(layout string, t time.Time) string { return t.Format(layout) },
}).Parse(templateContent))

func renderDetail(w io.Writer, rep *trivyReport, sev severitySet) error {
	return detailTmpl.Execute(w, filterResults(rep.Results, sev))
}

// ---------------------------------------------------------------------------
// Summary page
// ---------------------------------------------------------------------------

var summarySeverities = []string{"CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"}

type summaryRow struct {
	Stem    string
	Label   string
	OS      string
	Digest  string
	Scanned string
	Href    string
	Counts  map[string]int
	Total   int
	Highest string
}

func summarize(stem, jsonPath string, rep *trivyReport, sev severitySet) summaryRow {
	row := summaryRow{
		Stem:   stem,
		Label:  stem,
		OS:     "-",
		Href:   htmlSubdir + "/" + stem + ".html",
		Counts: map[string]int{},
	}
	if len(rep.Metadata.RepoTags) > 0 {
		row.Label = rep.Metadata.RepoTags[0]
	} else if rep.ArtifactName != "" {
		row.Label = filepath.Base(rep.ArtifactName)
	}
	if osInfo := rep.Metadata.OS; osInfo != nil {
		row.OS = strings.TrimSpace(osInfo.Family + " " + osInfo.Name)
	}
	row.Digest = strings.TrimPrefix(rep.Metadata.ImageID, "sha256:")
	if len(row.Digest) > 12 {
		row.Digest = row.Digest[:12]
	}
	if info, err := os.Stat(jsonPath); err == nil {
		row.Scanned = info.ModTime().Format("2006-01-02 15:04")
	}

	// Count what the detail page shows, so both pages always agree.
	for _, r := range filterResults(rep.Results, sev) {
		for _, v := range r.Vulnerabilities {
			row.Counts[strings.ToUpper(v.Severity)]++
			row.Total++
		}
	}
	for _, s := range summarySeverities {
		if row.Counts[s] > 0 {
			row.Highest = s
			break
		}
	}
	return row
}

type summaryData struct {
	CSS        htmltemplate.CSS
	Generated  string
	Severities []string
	Rows       []summaryRow
	Totals     map[string]int
	Total      int
}

var summaryTmpl = htmltemplate.Must(htmltemplate.New("summary").Funcs(htmltemplate.FuncMap{
	"lower": strings.ToLower,
	"title": func(s string) string { return s[:1] + strings.ToLower(s[1:]) },
}).Parse(summaryTemplateContent))

// detailCSS returns the <style> body of trivy-template.html so the summary
// page shares one stylesheet with the detail pages.
func detailCSS() htmltemplate.CSS {
	start := strings.Index(templateContent, "<style>")
	end := strings.Index(templateContent, "</style>")
	if start < 0 || end <= start {
		return ""
	}
	return htmltemplate.CSS(templateContent[start+len("<style>") : end])
}

func renderSummary(w io.Writer, rows map[string]summaryRow, sev severitySet) error {
	data := summaryData{
		CSS:       detailCSS(),
		Generated: time.Now().Format("2006-01-02 15:04"),
		Totals:    map[string]int{},
	}
	for _, s := range summarySeverities {
		if sev.has(s) {
			data.Severities = append(data.Severities, s)
		}
	}
	for _, r := range rows {
		data.Rows = append(data.Rows, r)
		for s, n := range r.Counts {
			data.Totals[s] += n
		}
		data.Total += r.Total
	}
	sort.Slice(data.Rows, func(i, j int) bool {
		a, b := data.Rows[i], data.Rows[j]
		if a.Counts["CRITICAL"] != b.Counts["CRITICAL"] {
			return a.Counts["CRITICAL"] > b.Counts["CRITICAL"]
		}
		if a.Counts["HIGH"] != b.Counts["HIGH"] {
			return a.Counts["HIGH"] > b.Counts["HIGH"]
		}
		if a.Total != b.Total {
			return a.Total > b.Total
		}
		if a.Label != b.Label {
			return a.Label < b.Label
		}
		return a.Stem < b.Stem
	})
	return summaryTmpl.Execute(w, data)
}

// ---------------------------------------------------------------------------
// Atomic file writes
// ---------------------------------------------------------------------------

// writeFileAtomic renders into path+".tmp" and renames it into place, so a
// failed or interrupted render never leaves a half-written file behind.
func writeFileAtomic(path string, render func(io.Writer) error) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp := path + ".tmp"
	f, err := os.Create(tmp)
	if err != nil {
		return err
	}
	if err := render(f); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, path)
}
