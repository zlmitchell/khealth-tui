package gather

import (
	"archive/tar"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"sigs.k8s.io/yaml"
)

// stage is the local directory a bundle is assembled in before it is packed.
// Paths given to it are bundle paths (forward slashes).
type stage struct{ dir string }

func (s stage) path(name string) string { return filepath.Join(s.dir, filepath.FromSlash(name)) }

func (s stage) create(name string) (*os.File, error) {
	p := s.path(name)
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return nil, err
	}
	return os.OpenFile(p, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
}

func (s stage) write(name string, b []byte) error {
	f, err := s.create(name)
	if err != nil {
		return err
	}
	_, err = f.Write(b)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	return err
}

func (s stage) writeJSON(name string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return s.write(name, append(b, '\n'))
}

func (s stage) writeYAML(name string, v any) error {
	b, err := yaml.Marshal(v)
	if err != nil {
		return err
	}
	return s.write(name, b)
}

// pack writes the staged tree as a gzipped tar at out, every entry under
// the top directory root/ (the bundle unpacks into one folder).
func (s stage) pack(out, root string) (int64, error) {
	f, err := os.OpenFile(out, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return 0, err
	}
	gz, _ := gzip.NewWriterLevel(f, gzip.BestSpeed)
	tw := tar.NewWriter(gz)
	err = filepath.WalkDir(s.dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		rel, err := filepath.Rel(s.dir, p)
		if err != nil {
			return err
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		h := &tar.Header{Name: root + "/" + filepath.ToSlash(rel), Mode: 0o600, Size: info.Size(), ModTime: info.ModTime(), Typeflag: tar.TypeReg}
		if err := tw.WriteHeader(h); err != nil {
			return err
		}
		src, err := os.Open(p)
		if err != nil {
			return err
		}
		_, err = io.Copy(tw, src)
		src.Close()
		return err
	})
	for _, c := range []io.Closer{tw, gz} {
		if cerr := c.Close(); err == nil {
			err = cerr
		}
	}
	st, serr := f.Stat()
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		os.Remove(out)
		return 0, err
	}
	if serr != nil {
		return 0, nil
	}
	return st.Size(), nil
}

// outPath turns --gather into a file path: a directory (existing, or
// written with a trailing separator) gets the standard name.
func outPath(out, context string, now time.Time) string {
	name := fmt.Sprintf("khealth-bundle-%s-%s.tar.gz", safeName(context), now.Format("20060102-150405"))
	if strings.HasSuffix(out, "/") || strings.HasSuffix(out, string(filepath.Separator)) {
		return filepath.Join(out, name)
	}
	if st, err := os.Stat(out); err == nil && st.IsDir() {
		return filepath.Join(out, name)
	}
	if !strings.HasSuffix(out, ".tar.gz") && !strings.HasSuffix(out, ".tgz") {
		return out + ".tar.gz"
	}
	return out
}

func safeName(s string) string {
	s = strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '.', r == '_', r == '-':
			return r
		}
		return '-'
	}, s)
	if s == "" {
		return "cluster"
	}
	return s
}
