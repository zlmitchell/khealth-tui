// Package stigdata embeds the DISA operating-system STIG rule tables generated
// by tools/stiggen from the DISA XCCDF (dl.dod.cyber.mil) joined with
// ComplianceAsCode, and derives from them the node-probe fragment (which
// files to stat, which directories to scan, which config files to dump).
//
// It deliberately depends on nothing else in the repo so that both the stig
// engine and the nodeinfo probe can import it.
package stigdata

import (
	"compress/gzip"
	"embed"
	"encoding/json"
	"fmt"
	"io"
	"path"
	"sort"
	"strings"
	"sync"
)

//go:embed data/*.json.gz
var files embed.FS

// Table is one generated STIG (one product / release).
type Table struct {
	Product            string `json:"product"` // rhel9, ubuntu2204 ...
	Name               string `json:"name"`    // DISA RHEL 9 STIG
	Version            string `json:"version"` // V2R9
	Date               string `json:"date"`    // 01 Jul 2026
	CAC                string `json:"cac"`     // ComplianceAsCode commit
	CACControlsVersion string `json:"cac_controls_version"`
	Rules              []Rule `json:"rules"`
}

// Rule is one STIG vulnerability with the ComplianceAsCode checks behind it.
type Rule struct {
	VID    string  `json:"vid"`    // V-258230
	STIGID string  `json:"stigid"` // RHEL-09-671010
	Cat    string  `json:"cat"`    // I, II, III
	Title  string  `json:"title"`
	Check  string  `json:"check"` // STIG check text
	Fix    string  `json:"fix"`   // STIG fix text
	Checks []Check `json:"checks"`
	Status string  `json:"status"` // automated, pending, not applicable, unmapped
}

// Check is one ComplianceAsCode rule: a template name with preprocessed
// parameters, or a custom (untemplated) OVAL check we cannot evaluate.
type Check struct {
	Rule     string            `json:"rule"`
	Template string            `json:"template"`
	Params   map[string]any    `json:"params"`
	Resolved map[string]string `json:"resolved,omitempty"` // XCCDF variable -> selected value
	Note     string            `json:"note,omitempty"`
}

// Str returns a string parameter ("" when absent or not a string).
func (c Check) Str(key string) string {
	s, _ := c.Params[key].(string)
	return s
}

// Bool returns a boolean parameter (accepts bool and "true"/"yes").
func (c Check) Bool(key string) bool {
	switch v := c.Params[key].(type) {
	case bool:
		return v
	case string:
		v = strings.ToLower(v)
		return v == "true" || v == "yes"
	}
	return false
}

// List returns a string-list parameter (a single string becomes one item).
func (c Check) List(key string) []string {
	switch v := c.Params[key].(type) {
	case []any:
		var out []string
		for _, x := range v {
			if s, ok := x.(string); ok {
				out = append(out, s)
			}
		}
		return out
	case string:
		if v != "" {
			return []string{v}
		}
	}
	return nil
}

// Owners returns the accepted owners of a file_owner / file_groupowner check
// (key UID_OR_NAME or GID_OR_NAME). ComplianceAsCode writes alternatives as a
// regex alternation ("adm|root", "syslog|root") and its OWNER/GROUP
// _REPRESENTED_WITH_ID flag does not reliably say whether the value is a
// number ("syslog" comes with GROUP_REPRESENTED_WITH_GID: true), so each
// alternative is classified by its own form: all digits is an id, anything
// else a name.
func (c Check) Owners(key string) []string {
	var out []string
	for _, w := range strings.Split(c.Str(key), "|") {
		if w = strings.TrimSpace(strings.Trim(strings.TrimSpace(w), "^$()")); w != "" {
			out = append(out, w)
		}
	}
	return out
}

// IsID reports whether an owner alternative (see Owners) is a numeric uid/gid.
func IsID(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// OwnerMatches reports whether a file's owner (name and numeric id) is one of
// the accepted alternatives.
func OwnerMatches(want []string, name, id string) bool {
	for _, w := range want {
		if IsID(w) && w == id || !IsID(w) && w == name {
			return true
		}
	}
	return false
}

// ExcludedFiles returns the EXCLUDED_FILES of a file template: shell globs
// over the file name (wtmp, btmp, lastlog under /var/log) that a recursive
// or FILE_REGEX scan skips.
func (c Check) ExcludedFiles() []string { return c.List("EXCLUDED_FILES") }

// FileRegex returns the FILE_REGEX for the i-th FILEPATH. ComplianceAsCode
// preprocesses it into a list parallel to FILEPATH; a single string applies to
// every path. "" means the path itself is the target; non-empty means the
// regular files inside the (directory) path whose names match.
func (c Check) FileRegex(i int) string {
	l := c.List("FILE_REGEX")
	switch {
	case len(l) == 1:
		return l[0]
	case i >= 0 && i < len(l):
		return l[i]
	}
	return ""
}

// Value returns the effective value for a template that takes either a
// literal (valueKey) or an XCCDF variable (varKey) resolved by the generator.
func (c Check) Value(valueKey, varKey string) string {
	if v := c.Str(valueKey); v != "" {
		return v
	}
	if vn := c.Str(varKey); vn != "" {
		return c.Resolved[vn]
	}
	return ""
}

var (
	mu     sync.Mutex
	tables = map[string]*Table{}
)

// Products lists the embedded product names.
func Products() []string {
	entries, _ := files.ReadDir("data")
	var out []string
	for _, e := range entries {
		out = append(out, strings.TrimSuffix(e.Name(), ".json.gz"))
	}
	sort.Strings(out)
	return out
}

// Load returns the table for a product (cached), or an error when none is
// embedded.
func Load(product string) (*Table, error) {
	mu.Lock()
	defer mu.Unlock()
	if t, ok := tables[product]; ok {
		return t, nil
	}
	f, err := files.Open(path.Join("data", product+".json.gz"))
	if err != nil {
		return nil, fmt.Errorf("no STIG table for %s", product)
	}
	defer f.Close()
	zr, err := gzip.NewReader(f)
	if err != nil {
		return nil, err
	}
	raw, err := io.ReadAll(zr)
	if err != nil {
		return nil, err
	}
	var t Table
	if err := json.Unmarshal(raw, &t); err != nil {
		return nil, fmt.Errorf("%s: %w", product, err)
	}
	tables[product] = &t
	return &t, nil
}

// CheckID names a check within a rule; it is what the probe's VIOL lines
// carry so results can be matched back.
func CheckID(vid string, i int) string { return fmt.Sprintf("%s:%d", vid, i) }
