package helmcheck

import "testing"

func TestCompareVersions(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"1.2.3", "1.2.4", -1}, {"v2.0.0", "1.9.9", 1}, {"1.2.3", "1.2.3", 0},
		{"1.2.3-rc1", "1.2.3", -1}, {"1.10.0", "1.9.0", 1}, {"15.0.1+build", "15.0.1", 0},
	}
	for _, c := range cases {
		if got := CompareVersions(c.a, c.b); got != c.want {
			t.Errorf("Compare(%s,%s)=%d want %d", c.a, c.b, got, c.want)
		}
	}
	if !IsPrerelease("1.0.0-alpha.1") || IsPrerelease("1.0.0+meta") {
		t.Errorf("prerelease detection")
	}
}
