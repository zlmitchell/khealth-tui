package config

// Shell completion. The shell gets a stub of a few lines that calls the
// binary back (`khealth __complete <cword> <words...>`); every candidate is
// computed here, in Go, from the same FlagSet Load() parses with. Nothing
// has to be kept in step with a second copy of the flag list, and the
// completer can read what a shell script cannot parse reliably: the
// kubeconfig, known_hosts and ~/.ssh/config.

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// completeCommand is the hidden first argument the shell stub passes to ask
// for candidates. Not a flag: the words being completed are another command
// line, and the flag parser must not see them.
const completeCommand = "__complete"

// loadedFlagSet is the FlagSet the last Load() registered. Complete() is
// always handed that same FlagSet directly, so nothing in the completion
// path depends on this; it exists so the tests can check the flag names
// this file does name by hand (flagValues, pathFlags, dirFlags) against
// the real ones.
var loadedFlagSet *flag.FlagSet

// completeArgs answers a `khealth __complete <cword> <words...>` call.
func completeArgs(fs *flag.FlagSet, args []string) []string {
	if len(args) == 0 {
		return nil
	}
	cword, err := strconv.Atoi(args[0])
	if err != nil {
		return nil
	}
	return Complete(fs, cword, args[1:])
}

// optionalString is a flag that may be given with or without a value:
// --completions and --completions=zsh both work. Go's flag package only
// allows that for flags that claim to be booleans, so a bare use arrives
// here as "true" and is reported as set-but-empty.
type optionalString struct {
	set   bool
	value string
}

func (o *optionalString) String() string {
	if o == nil {
		return ""
	}
	return o.value
}

func (o *optionalString) Set(s string) error {
	o.set = true
	if s != "true" { // a bare --completions
		o.value = s
	}
	return nil
}

func (o *optionalString) IsBoolFlag() bool { return true }

// isShell reports whether s names a shell we can complete, so that
// `--completions zsh` (with a space, which the flag package would leave as
// a positional argument) is understood rather than read as a node to
// bootstrap from.
func isShell(s string) bool {
	_, ok := completionStubs[strings.ToLower(s)]
	return ok
}

// FilesSentinel asks the shell stub to fall back to its own filename
// completion: paths are the shell's job (it knows the cursor's quoting and
// can mark directories).
//
// Printable on purpose. A shell string cannot hold a NUL byte, so a
// \0-prefixed sentinel collapses to the empty string and the stub's case
// pattern degenerates into one that matches everything - every completion
// then comes back as a filename.
const FilesSentinel = "__khealth_files__"

// DirsSentinel is FilesSentinel for flags that take a directory.
const DirsSentinel = "__khealth_dirs__"

// completionStubs are the shell snippets `--completions <shell>` prints.
// They never change when a flag is added: everything is computed by the
// __complete call.
var completionStubs = map[string]string{
	"bash": `# khealth bash completion. Candidates come from the binary:
#   eval "$(khealth --completions bash)"      # this shell
#   khealth --install-completions             # permanently
_khealth() {
	local IFS=$'\n' out
	out="$("${COMP_WORDS[0]}" __complete "$COMP_CWORD" "${COMP_WORDS[@]:1}" 2>/dev/null)" || return
	case "$out" in
	__khealth_files__)
		COMPREPLY=($(compgen -f -- "${COMP_WORDS[COMP_CWORD]}"))
		compopt -o filenames 2>/dev/null
		return
		;;
	__khealth_dirs__)
		COMPREPLY=($(compgen -d -- "${COMP_WORDS[COMP_CWORD]}"))
		compopt -o filenames 2>/dev/null
		return
		;;
	esac
	COMPREPLY=($out)
	# a single flag completion should not get a trailing space when it wants a value
	case "${COMPREPLY[0]}" in
	*=) compopt -o nospace 2>/dev/null ;;
	esac
}
complete -F _khealth khealth
`,
	"zsh": `# khealth zsh completion. Candidates come from the binary:
#   eval "$(khealth --completions zsh)"       # this shell
#   khealth --install-completions             # permanently
_khealth() {
	local -a out
	out=("${(@f)$("${words[1]}" __complete "$((CURRENT - 1))" "${words[@]:1}" 2>/dev/null)}")
	case "$out[1]" in
	__khealth_files__) _files; return ;;
	__khealth_dirs__) _files -/; return ;;
	esac
	compadd -- "${out[@]}"
}
compdef _khealth khealth
`,
	"fish": `# khealth fish completion. Candidates come from the binary:
#   khealth --completions fish | source       # this shell
#   khealth --install-completions             # permanently
function __khealth_complete
	set -l tokens (commandline -opc) (commandline -ct)
	khealth __complete (math (count $tokens) - 1) $tokens[2..-1] 2>/dev/null
end
complete -c khealth -f -a '(__khealth_complete)'
`,
}

// CompletionShells lists the shells --completions accepts.
func CompletionShells() []string {
	out := make([]string, 0, len(completionStubs))
	for s := range completionStubs {
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

// CompletionScript returns the shell stub for shell.
func CompletionScript(shell string) (string, error) {
	if shell == "" {
		shell = "bash"
	}
	s, ok := completionStubs[strings.ToLower(shell)]
	if !ok {
		return "", fmt.Errorf("no completion for %q (have %s)", shell, strings.Join(CompletionShells(), ", "))
	}
	return s, nil
}

// completionPath is where InstallCompletion writes the stub for shell.
func completionPath(shell string) (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	switch shell {
	case "bash":
		dir := os.Getenv("XDG_DATA_HOME")
		if dir == "" {
			dir = filepath.Join(home, ".local", "share")
		}
		return filepath.Join(dir, "bash-completion", "completions", "khealth"), nil
	case "zsh":
		return filepath.Join(home, ".zsh", "completions", "_khealth"), nil
	case "fish":
		dir := os.Getenv("XDG_CONFIG_HOME")
		if dir == "" {
			dir = filepath.Join(home, ".config")
		}
		return filepath.Join(dir, "fish", "completions", "khealth.fish"), nil
	}
	return "", fmt.Errorf("no completion for %q (have %s)", shell, strings.Join(CompletionShells(), ", "))
}

// InstallCompletion writes the stub for shell and returns the path. Unlike
// --init-config it overwrites: the file is generated, never edited.
func InstallCompletion(shell string) (string, error) {
	if shell == "" {
		shell = "bash"
	}
	shell = strings.ToLower(shell)
	script, err := CompletionScript(shell)
	if err != nil {
		return "", err
	}
	path, err := completionPath(shell)
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return "", err
	}
	if err := os.WriteFile(path, []byte(script), 0o644); err != nil {
		return "", err
	}
	return path, nil
}

// flagValues are the flags whose values are a fixed set. The lists are the
// ones Load and the SSH runner accept, so completion cannot offer a value
// that is then rejected.
var flagValues = map[string][]string{
	"become":      {"auto", "sudo", "dzdo", "doas", "none"},
	"theme":       {"auto", "light", "dark"},
	"ssh-address": {"InternalIP", "ExternalIP", "Hostname"},
	"completions": {"bash", "zsh", "fish"},
	"ssh-port":    {"22"},
	"refresh":     {"10s", "30s", "1m", "5m"},
}

// pathFlags take a file; dirFlags take a directory. The shell completes
// both (FilesSentinel / DirsSentinel).
var pathFlags = map[string]bool{
	"config": true, "kubeconfig": true, "ssh-key": true, "perf-log": true,
	"export": true, "bootstrap-out": true, "bootstrap-kubeconfig": true,
}
var dirFlags = map[string]bool{"export-dir": true}

// isBoolFlag reports whether f is a boolean flag, which in Go's flag
// package can only take a value as -flag=x.
func isBoolFlag(f *flag.Flag) bool {
	bf, ok := f.Value.(interface{ IsBoolFlag() bool })
	return ok && bf.IsBoolFlag()
}

// Complete prints the completion candidates for a command line, one per
// line, and is what the shell stub calls. cword is the index of the word
// the cursor is on and words are the arguments after the program name, so
// words[cword-1] is the word being completed (cword 0 is the program).
//
// fs must be the FlagSet Load builds, so the flag list is never a copy.
func Complete(fs *flag.FlagSet, cword int, words []string) []string {
	cur := ""
	if i := cword - 1; i >= 0 && i < len(words) {
		cur = words[i]
	}
	prev := ""
	if i := cword - 2; i >= 0 && i < len(words) {
		prev = words[i]
	}

	// --flag=value: complete the value part
	if name, val, ok := strings.Cut(cur, "="); ok && strings.HasPrefix(name, "-") {
		vals := valuesFor(fs, strings.TrimLeft(name, "-"))
		if len(vals) == 1 && (vals[0] == FilesSentinel || vals[0] == DirsSentinel) {
			return vals
		}
		return prefixed(vals, val, name+"=")
	}

	// a value for the flag before the cursor (bools never take one)
	if strings.HasPrefix(prev, "-") && !strings.Contains(prev, "=") {
		name := strings.TrimLeft(prev, "-")
		if f := fs.Lookup(name); f != nil && !isBoolFlag(f) {
			return match(valuesFor(fs, name), cur)
		}
	}

	if strings.HasPrefix(cur, "-") {
		return match(flagNames(fs), cur)
	}

	// positional: [user@]server-node
	user := ""
	host := cur
	if i := strings.LastIndex(cur, "@"); i >= 0 {
		user, host = cur[:i+1], cur[i+1:]
	}
	return prefixed(knownHosts(), host, user)
}

// flagNames lists every registered flag as the shell should offer it. A
// flag that takes a value is offered as "--name=" so the value can be
// completed in the same word.
func flagNames(fs *flag.FlagSet) []string {
	var out []string
	fs.VisitAll(func(f *flag.Flag) {
		if f.Name == completeCommand {
			return // internal
		}
		if isBoolFlag(f) {
			out = append(out, "--"+f.Name)
			return
		}
		out = append(out, "--"+f.Name+"=")
	})
	sort.Strings(out)
	return out
}

// valuesFor returns the candidate values of one flag.
func valuesFor(fs *flag.FlagSet, name string) []string {
	if f := fs.Lookup(name); f != nil && isBoolFlag(f) {
		return []string{"true", "false"}
	}
	switch {
	case pathFlags[name]:
		return []string{FilesSentinel}
	case dirFlags[name]:
		return []string{DirsSentinel}
	case name == "context":
		return kubeContexts()
	case name == "bastion":
		return knownHosts()
	}
	return flagValues[name]
}

func match(all []string, prefix string) []string {
	var out []string
	for _, s := range all {
		if strings.HasPrefix(s, prefix) {
			out = append(out, s)
		}
	}
	return out
}

// prefixed filters all by prefix and puts pre back in front of each match,
// so "root@10.0" completes to "root@10.0.0.1" rather than "10.0.0.1".
func prefixed(all []string, prefix, pre string) []string {
	out := match(all, prefix)
	if pre == "" {
		return out
	}
	for i := range out {
		out[i] = pre + out[i]
	}
	return out
}

// kubeContexts reads the context names out of every file in KUBECONFIG (or
// ~/.kube/config). Parsed as YAML, so a name under clusters: or users: is
// never mistaken for a context.
func kubeContexts() []string {
	var files []string
	if kc := os.Getenv("KUBECONFIG"); kc != "" {
		files = filepath.SplitList(kc)
	} else if home, err := os.UserHomeDir(); err == nil {
		files = []string{filepath.Join(home, ".kube", "config")}
	}
	seen := map[string]bool{}
	var out []string
	for _, f := range files {
		b, err := os.ReadFile(expand(f))
		if err != nil {
			continue
		}
		var kc struct {
			Contexts []struct {
				Name string `yaml:"name"`
			} `yaml:"contexts"`
		}
		if yaml.Unmarshal(b, &kc) != nil {
			continue
		}
		for _, c := range kc.Contexts {
			if c.Name != "" && !seen[c.Name] {
				seen[c.Name] = true
				out = append(out, c.Name)
			}
		}
	}
	sort.Strings(out)
	return out
}

// systemKnownHosts is the machine-wide known_hosts. A variable so the
// tests can point it somewhere empty: setting HOME does not hide it, and a
// CI runner ships one (github.com, ssh.dev.azure.com).
var systemKnownHosts = "/etc/ssh/ssh_known_hosts"

// knownHosts lists the hosts worth completing a [user@]server-node with:
// known_hosts (one line names every alias, and a host appears once per key
// type, so they are deduplicated) and the Host entries of ~/.ssh/config.
// Hashed known_hosts entries cannot be read back and are skipped.
func knownHosts() []string {
	seen := map[string]bool{}
	var out []string
	add := func(h string) {
		h = strings.TrimSpace(h)
		h = strings.TrimPrefix(h, "[")
		if i := strings.Index(h, "]:"); i >= 0 {
			h = h[:i]
		}
		if h == "" || strings.HasPrefix(h, "|") || strings.ContainsAny(h, "*?") || seen[h] {
			return
		}
		seen[h] = true
		out = append(out, h)
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return nil
	}
	for _, p := range []string{filepath.Join(home, ".ssh", "known_hosts"), systemKnownHosts} {
		f, err := os.Open(p)
		if err != nil {
			continue
		}
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			for _, h := range strings.Split(strings.Fields(line)[0], ",") {
				add(h)
			}
		}
		f.Close()
	}
	if f, err := os.Open(filepath.Join(home, ".ssh", "config")); err == nil {
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			fields := strings.Fields(sc.Text())
			if len(fields) >= 2 && strings.EqualFold(fields[0], "host") {
				for _, h := range fields[1:] {
					add(h)
				}
			}
		}
		f.Close()
	}
	sort.Strings(out)
	return out
}
