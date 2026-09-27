package logs

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

func TestNeedLiterals(t *testing.T) {
	for expr, want := range map[string][]string{
		`slow fdatasync|took too long`:               {"slow fdatasync", "took too long"},
		`Waiting for etcd (to become|cluster)`:       {"waiting for etcd to become", "waiting for etcd cluster"},
		`(rke2|k3s) is up and running`:               {"rke2 is up and running", "k3s is up and running"},
		`level=warn(ing)?|\bW[0-9]{4} `:              nil,                           // "w" is too short to be worth checking
		`(?i)(failed|error|unable).{0,60}(upload|x)`: {"failed", "error", "unable"}, // the "x" branch is too short, the other one serves
		`dial tcp [0-9.]+:9345: connect`:             {":9345: connect"},
		`.*`:                                         nil,
	} {
		if got := needLiterals(expr); !reflect.DeepEqual(got, want) {
			t.Errorf("%s: %q, want %q", expr, got, want)
		}
	}
}

// Weak literals let routine lines through the prefilter: Go's parser
// factors Start(ing|ed) and an optional (ment)? broke the chain, leaving
// "start" and "started", which every "... started for volume" line has.
func TestPrefilterSelective(t *testing.T) {
	routine := `I0926 10:22:00.000 12 reconciler.go:100] "operationExecutor.VerifyControllerAttachedVolume started for volume" pod="ns-1/pod-1"`
	if MayMatch(routine) {
		t.Errorf("a routine kubelet line passes the prefilter")
	}
	for _, p := range []string{"rke2-start", "defrag"} {
		if need := Find(p).need; need == nil || shortest(need) < 10 {
			t.Errorf("%s: literals %q", p, need)
		}
	}
}

// The prefilter may only skip lines the regexp would not match. Checked
// against every string literal of every test file in the repository (the
// checks, logs and ui tests hold hundreds of real journal and klog lines)
// plus each pattern's own literals.
func TestPrefilterNeverHidesAMatch(t *testing.T) {
	var corpus []string
	root := filepath.Join("..", "..")
	_ = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(p, "_test.go") {
			return nil
		}
		f, err := parser.ParseFile(token.NewFileSet(), p, nil, 0)
		if err != nil {
			return nil
		}
		ast.Inspect(f, func(n ast.Node) bool {
			if lit, ok := n.(*ast.BasicLit); ok && lit.Kind == token.STRING {
				if s, err := strconv.Unquote(lit.Value); err == nil {
					corpus = append(corpus, strings.Split(s, "\n")...)
				}
			}
			return true
		})
		return nil
	})
	for i := range patterns {
		corpus = append(corpus, patterns[i].need...)
	}
	if len(corpus) < 1000 {
		t.Fatalf("corpus too small (%d lines): test files not found?", len(corpus))
	}
	checked := 0
	for _, line := range corpus {
		tl := strings.TrimSpace(line)
		lower := strings.ToLower(tl)
		for i := range patterns {
			p := &patterns[i]
			if p.Re.MatchString(tl) {
				checked++
				if !p.matches(tl, lower) {
					t.Errorf("prefilter of %s (%q) hides a match: %q", p.Name, p.need, tl)
				}
				var scratch []byte
				if !MayMatch(line) || !MayMatchBytes([]byte(line), &scratch) {
					t.Errorf("MayMatch drops a line %s matches: %q", p.Name, line)
				}
			}
		}
	}
	if checked < 100 {
		t.Errorf("only %d matching lines in the corpus: the property is barely exercised", checked)
	}
}
