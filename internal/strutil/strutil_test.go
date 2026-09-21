package strutil

import (
	"strings"
	"testing"
	"time"
)

func TestFirstLine(t *testing.T) {
	long := strings.Repeat("x", 400)
	for in, want := range map[string]string{
		"  first \nsecond": "first",
		"only":             "only",
		"\n\nlead":         "lead",
		long:               long[:200] + "...",
	} {
		if got := FirstLine(in); got != want {
			t.Errorf("FirstLine(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestTrunc(t *testing.T) {
	if TruncStr("abcdef", 3) != "abc..." || TruncStr("abc", 3) != "abc" {
		t.Error("TruncStr")
	}
	l := []string{"a", "b", "c", "d"}
	if TruncList(l, 2) != "a, b (+2 more)" || TruncList(l, 4) != "a, b, c, d" {
		t.Error("TruncList")
	}
}

func TestFirstNonEmpty(t *testing.T) {
	if FirstNonEmpty("", "x", "y") != "x" || FirstNonEmpty("", "") != "" || PrefixIf("p", "") != "" || PrefixIf("p", "s") != "ps" {
		t.Error("FirstNonEmpty/PrefixIf")
	}
}

func TestSlices(t *testing.T) {
	if got := Uniq([]string{"b", "a", "b", "c", "a"}); strings.Join(got, "") != "bac" {
		t.Errorf("Uniq: %v", got)
	}
	if got := SortedKeys(map[string]int{"b": 1, "a": 2}); strings.Join(got, "") != "ab" {
		t.Errorf("SortedKeys: %v", got)
	}
	if AtoiOr(" 42 ", 7) != 42 || AtoiOr("x", 7) != 7 || AtoiOr("", 7) != 7 {
		t.Error("AtoiOr")
	}
}

func TestHuman(t *testing.T) {
	if HumanBytes(512) != "512B" || HumanBytes(1536) != "1.5KiB" || HumanBytes(3<<30) != "3.0GiB" || HumanBytes(2e15) != "1819.0TiB" {
		t.Errorf("HumanBytes: %s %s %s %s", HumanBytes(512), HumanBytes(1536), HumanBytes(3<<30), HumanBytes(2e15))
	}
	for d, want := range map[time.Duration]string{
		45 * time.Second:             "45s",
		-3 * time.Minute:             "3m",
		2*time.Hour + 5*time.Minute:  "2h05m",
		3*24*time.Hour + 4*time.Hour: "3d4h",
		40 * 24 * time.Hour:          "40d",
	} {
		if got := HumanDur(d); got != want {
			t.Errorf("HumanDur(%v) = %q, want %q", d, got, want)
		}
	}
}

func TestURLHost(t *testing.T) {
	if URLHost("https://[fd00::1]:2380") != "fd00::1" || URLHost("https://10.0.0.1:2380") != "10.0.0.1" || URLHost("https://etcd-1") != "etcd-1" || URLHost("") != "" || URLHost("10.0.0.1:2380") != "" {
		t.Error("URLHost")
	}
}
