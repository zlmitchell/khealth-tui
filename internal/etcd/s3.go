package etcd

import (
	"regexp"
	"strconv"
	"strings"
	"time"
)

// S3Check is the result of testing the snapshot S3 endpoint from a node: can
// the node resolve it, connect, and complete TLS with the configured CA. No
// credentials are involved; any HTTP status (403 is typical for an anonymous
// request) means the endpoint is reachable.
type S3Check struct {
	Node     string
	URL      string
	OK       bool
	HTTPCode int
	Detail   string
	Checked  time.Time
}

// S3CheckScript builds the node-side probe. caFile is a path on the node,
// caPEM is certificate content (from the etcd-s3-config-secret) written to a
// temp file for the check; skipVerify mirrors etcd-s3-skip-ssl-verify.
func S3CheckScript(url, caFile, caPEM string, skipVerify bool) string {
	var b strings.Builder
	b.WriteString("export LC_ALL=C\nCA=''\n")
	if caPEM != "" && pemSafe(caPEM) {
		b.WriteString("CA=$(mktemp /tmp/khealth-s3-ca.XXXXXX) && cat > \"$CA\" <<'KHEALTH_EOF_CA'\n")
		b.WriteString(strings.TrimSpace(caPEM))
		b.WriteString("\nKHEALTH_EOF_CA\n")
	} else if caFile != "" {
		b.WriteString("CA='" + clean(caFile) + "'\n")
	}
	b.WriteString("URL='" + clean(url) + "'\n")
	b.WriteString("if ! command -v curl >/dev/null 2>&1; then echo 'curl-missing'; else\n")
	b.WriteString("  ARGS='-sS -m 8 -o /dev/null -w %{http_code}'\n")
	if skipVerify {
		b.WriteString("  ARGS=\"$ARGS -k\"\n")
	}
	b.WriteString("  [ -n \"$CA\" ] && [ -r \"$CA\" ] && ARGS=\"$ARGS --cacert $CA\"\n")
	b.WriteString("  [ -n \"$CA\" ] && [ ! -r \"$CA\" ] && echo \"ca-missing=$CA\"\n")
	b.WriteString("  curl $ARGS \"$URL/\" 2>&1; echo\n")
	b.WriteString("fi\n")
	if caPEM != "" {
		b.WriteString("case \"$CA\" in /tmp/khealth-s3-ca.*) rm -f \"$CA\";; esac\n")
	}
	return b.String()
}

var pemChars = regexp.MustCompile(`^[A-Za-z0-9+/=\s-]+$`)

func pemSafe(pem string) bool {
	return pemChars.MatchString(pem) && !strings.Contains(pem, "KHEALTH_EOF_CA")
}

// S3URL turns the etcd-s3-endpoint value into a URL: rke2 defaults to
// s3.amazonaws.com over https unless etcd-s3-insecure is set.
func S3URL(endpoint string, insecure bool) string {
	ep := strings.TrimSpace(endpoint)
	if ep == "" {
		ep = "s3.amazonaws.com"
	}
	if strings.HasPrefix(ep, "http://") || strings.HasPrefix(ep, "https://") {
		return strings.TrimRight(ep, "/")
	}
	if insecure {
		return "http://" + ep
	}
	return "https://" + ep
}

var httpCodeRe = regexp.MustCompile(`^\d{3}$`)

// ParseS3Check interprets the script output. curl -w prints the HTTP code
// even after a transport error (as 000), so the error line wins.
func ParseS3Check(node, url, out string) S3Check {
	c := S3Check{Node: node, URL: url, Checked: time.Now()}
	var caMissing, curlErr, code string
	for _, l := range lines(out) {
		switch {
		case strings.HasPrefix(l, "ca-missing="):
			caMissing = strings.TrimPrefix(l, "ca-missing=")
		case strings.HasPrefix(l, "curl:"):
			curlErr = strings.TrimSpace(strings.TrimPrefix(l, "curl:"))
		case l == "curl-missing":
			c.Detail = "curl not installed on node"
			return c
		case httpCodeRe.MatchString(l):
			code = l
		default:
			if curlErr == "" {
				curlErr = l // e.g. "ssh: ..." from the caller
			}
		}
	}
	caNote := ""
	if caMissing != "" {
		caNote = " (configured CA " + caMissing + " not readable"
	}
	switch {
	case code != "" && code != "000":
		c.HTTPCode, _ = strconv.Atoi(code)
		c.OK = true
		c.Detail = "HTTP " + code
		if caNote != "" {
			c.Detail += caNote + ", verified with system CAs)"
		}
	case curlErr != "":
		c.Detail = curlErr
		if caNote != "" {
			c.Detail += caNote + ")"
		}
	default:
		c.Detail = "no output"
	}
	return c
}
