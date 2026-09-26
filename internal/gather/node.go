package gather

import (
	"archive/tar"
	"bufio"
	"compress/gzip"
	_ "embed"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/zlmitchell/khealth-tui/internal/nodeinfo"
)

//go:embed scripts/gather.sh
var gatherScript string

// nodeOpts sizes one node's part of the bundle.
type nodeOpts struct {
	BudgetKB  int64
	FileBytes int64
	PodBytes  int64
	Minutes   int
	PodGlobs  []string // /var/log/pods/<ns>_<pod>_<uid> directory globs to copy
}

var safeGlob = regexp.MustCompile(`^[A-Za-z0-9._*-]{1,300}$`)

// nodeScript is gather.sh with its placeholders filled, after the node
// probe's prelude (mask, maskreg, asyaml, runcri, the data dirs).
func nodeScript(o nodeOpts) string {
	var globs []string
	for _, g := range o.PodGlobs {
		if safeGlob.MatchString(g) {
			globs = append(globs, g)
		}
	}
	return nodeinfo.Prelude() + strings.NewReplacer(
		"__BUDGET_KB__", fmt.Sprint(max(o.BudgetKB, 1024)),
		"__FILE_BYTES__", fmt.Sprint(max(o.FileBytes, 4096)),
		"__POD_BYTES__", fmt.Sprint(max(o.PodBytes, 4096)),
		"__MINUTES__", fmt.Sprint(max(o.Minutes, 1)),
		"__PODGLOBS__", strings.Join(globs, " "),
	).Replace(gatherScript)
}

// staticPodGlobs are the control-plane static pods: their logs on disk are
// the ones that survive an apiserver that cannot serve them.
var staticPodGlobs = []string{
	"kube-system_etcd-*", "kube-system_kube-apiserver-*", "kube-system_kube-controller-manager-*",
	"kube-system_kube-scheduler-*", "kube-system_kube-proxy-*", "kube-system_cloud-controller-manager-*",
}

// systemPodGlobs widen the on-disk pod logs to the platform namespaces when
// the API is down and cannot hand them out.
var systemPodGlobs = []string{
	"kube-system_*", "kube-flannel_*", "cattle-*", "calico-*", "tigera-operator_*", "cilium*",
	"longhorn-system_*", "rook-*", "trident*", "cert-manager_*", "ingress-nginx_*", "metallb-*",
}

// errTooBig stops a node stream that runs past its hard limit.
var errTooBig = errors.New("node archive exceeds its limit")

// tarMarker is the line gather.sh prints right before the archive.
const tarMarker = "===KHEALTH-GATHER-TAR"

// readNodeTar unpacks one node's archive (gzip or plain tar, as gather.sh
// could produce it) under dir, refusing names that leave dir and stopping
// at limit bytes of content. Whatever precedes the marker line (a login
// banner, shell profile output) is skipped.
func readNodeTar(r io.Reader, dir string, limit int64) (files int, n int64, err error) {
	br := bufio.NewReader(r)
	var pre int
	for {
		line, err := br.ReadString('\n')
		if strings.TrimRight(line, "\r\n") == tarMarker {
			break
		}
		pre += len(line)
		if err != nil || pre > 1<<20 {
			return 0, 0, errors.New("no archive in the node's output (the script stopped before packing; see _gather/stderr.txt)")
		}
	}
	return extract(br, dir, limit)
}

// extract unpacks a gzipped or plain tar under dir, refusing names that
// leave dir and stopping at limit bytes of content.
func extract(r io.Reader, dir string, limit int64) (files int, n int64, err error) {
	br, ok := r.(*bufio.Reader)
	if !ok {
		br = bufio.NewReader(r)
	}
	var src io.Reader = br
	if b, _ := br.Peek(2); len(b) == 2 && b[0] == 0x1f && b[1] == 0x8b {
		gz, err := gzip.NewReader(br)
		if err != nil {
			return 0, 0, err
		}
		defer gz.Close()
		src = gz
	}
	tr := tar.NewReader(src)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			return files, n, nil
		}
		if err != nil {
			return files, n, err
		}
		if h.Typeflag != tar.TypeReg {
			continue
		}
		name := path.Clean(strings.TrimPrefix(h.Name, "./"))
		if name == "." || name == ".." || strings.HasPrefix(name, "../") || path.IsAbs(name) {
			continue
		}
		if n+h.Size > limit {
			return files, n, errTooBig
		}
		dst := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
			return files, n, err
		}
		f, err := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
		if err != nil {
			return files, n, err
		}
		c, err := io.Copy(f, io.LimitReader(tr, h.Size))
		f.Close()
		n += c
		files++
		if err != nil {
			return files, n, err
		}
	}
}
