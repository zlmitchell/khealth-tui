// Package config holds the runtime configuration for khealth: defaults,
// the optional YAML config file and command-line flag overrides.
package config

import (
	_ "embed"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Config is the top-level configuration.
type Config struct {
	// Flags holds the names of the command-line flags that were given, so a
	// remembered per-cluster setting (ssh user/key from a bootstrapped
	// context) never overrides what the operator typed.
	Flags map[string]bool `yaml:"-"`

	Kubeconfig string        `yaml:"kubeconfig"`
	Context    string        `yaml:"context"`
	Namespace  string        `yaml:"namespace"`
	Refresh    time.Duration `yaml:"refresh"`
	// Theme picks the light or dark palette: auto (ask the terminal for its
	// background, internal/termtheme), light or dark for a terminal that does
	// not answer and reads as dark (--theme, KHT_THEME).
	Theme string `yaml:"theme"`
	// HeavyEvery is the cadence (in refresh cycles) of a demand tier while
	// a tab shows it or collect.always pins it: journal, image inventories,
	// PV du, config facts (docs/ARCHITECTURE.md §7).
	HeavyEvery int        `yaml:"heavy_every"`
	Collect    Collect    `yaml:"collect"`
	SSH        SSH        `yaml:"ssh"`
	Etcd       Etcd       `yaml:"etcd"`
	Helm       Helm       `yaml:"helm"`
	Logs       Logs       `yaml:"logs"`
	Actions    Actions    `yaml:"actions"`
	Thresholds Thresholds `yaml:"thresholds"`

	// Perf tunes and records the tool's own footprint (docs/PERFORMANCE.md).
	Perf Perf `yaml:"perf"`

	// Export is where `e` writes the findings report (JSON + XLSX).
	Export Export `yaml:"export"`

	// Namespaces names what this deployment treats as infrastructure.
	Namespaces Namespaces `yaml:"namespaces"`

	Diag bool `yaml:"-"` // --diag: print API/permission diagnostics and exit

	// Bootstrap (--bootstrap-kubeconfig): build a kubeconfig over SSH from a
	// server node before starting, for operators who have node access but no
	// kubeconfig (see internal/bootstrap).
	Bootstrap Bootstrap `yaml:"-"`
}

// Export configures the report files `e` writes (internal/export) and the
// one-shot --export mode.
// Namespaces extends the built-in notion of a system namespace (kube-*,
// cattle-*, longhorn-*, ...) with this deployment's own: the STIG/CIS rules
// about privileged pods, NetworkPolicies and PSA labels, and the "user
// pods on control-plane nodes" table, leave those alone. The namespaces the
// PSA admission config exempts count as system too, without listing them.
type Namespaces struct {
	System []string `yaml:"system"` // extra system namespaces or prefixes (a trailing - or * marks a prefix)
	CNI    []string `yaml:"cni"`    // extra CNI agent pod names/prefixes (for MTU and restart checks)
}

type Export struct {
	Dir string `yaml:"dir"` // directory for khealth-<context>-<timestamp>.json/.xlsx (default: current directory)

	// Out (--export): run one collection cycle without the TUI, write the
	// report and exit. A directory gets both files under the standard name;
	// a path ending in .json or .xlsx gets that one file.
	Out string `yaml:"-"`
	// Scan (--export-scan) includes the security scan in the one-shot export:
	// the STIG/CIS rules from the API data and the OS STIG facts over SSH.
	Scan bool `yaml:"-"`
	// Heavy (--export-heavy) includes the heavy node tiers (journal, images,
	// registry pull dry run) so their findings are in the report.
	Heavy bool `yaml:"-"`
}

// Bootstrap holds the --bootstrap-* flags.
type Bootstrap struct {
	Hosts []string // server nodes to fetch the admin kubeconfig from, in order
	Out   string   // output path (default ~/.kube/khealth-<cluster>.yaml)
	Name  string   // cluster/context name (default: from the endpoint DNS name or node hostname)
	Fresh bool     // do not reuse an existing ~/.kube/khealth-*.yaml for the cluster
}

// Perf configures footprint measurement and the API-side load reducers.
type Perf struct {
	Log   string `yaml:"log"`   // JSONL file: one record per refresh cycle (--perf-log)
	Pprof string `yaml:"pprof"` // listen address for net/http/pprof, e.g. 127.0.0.1:6060 (--pprof)
	// WatchCache lists with resourceVersion=0 so the apiserver answers from
	// its watch cache instead of doing a quorum read against etcd per list.
	WatchCache bool `yaml:"watch_cache"`
	// Protobuf asks for application/vnd.kubernetes.protobuf on typed lists
	// (smaller, cheaper for the apiserver to encode than JSON).
	Protobuf bool `yaml:"protobuf"`
	// DiscoveryTTL / ConfigzTTL cache API discovery + CRD definitions and the
	// per-node kubelet configz between refreshes (0 = fetch every cycle).
	DiscoveryTTL time.Duration `yaml:"discovery_ttl"`
	ConfigzTTL   time.Duration `yaml:"configz_ttl"`
	// DeniedTTL: API calls the token is refused (403) or whose resource type
	// does not exist are not retried for this long (R retries them).
	DeniedTTL time.Duration `yaml:"denied_ttl"`
}

// Actions configures the (opt-out) mutating operations run through CLIs.
type Actions struct {
	Enabled    bool   `yaml:"enabled"`
	HelmBinary string `yaml:"helm_binary"`
}

// SSH configures how nodes are reached over SSH.
type SSH struct {
	Enabled  bool   `yaml:"enabled"`
	User     string `yaml:"user"`
	Key      string `yaml:"key"`
	Password string `yaml:"password"` // fallback when public key auth fails (prefer --ask-pass / KHT_SSH_PASSWORD)
	AskPass  bool   `yaml:"ask_pass"` // prompt for the password at startup
	Port     int    `yaml:"port"`
	// Sudo: false disables privilege escalation entirely (same as become: none).
	Sudo bool `yaml:"sudo"`
	// Become is the tool used to run the probes as root when User is not
	// root: "auto" (default: probe sudo, dzdo, doas in that order and keep
	// the first that works on each host), "sudo", "dzdo", "doas" or "none".
	// NOPASSWD is used when granted; otherwise the password (BecomePassword,
	// then Password / --ask-pass) is fed on stdin for sudo and dzdo (doas
	// cannot read one).
	Become string `yaml:"become"`
	// BecomePassword is the escalation password when it differs from the SSH
	// password (KHT_BECOME_PASSWORD).
	BecomePassword string            `yaml:"become_password"`
	Timeout        time.Duration     `yaml:"timeout"`
	Address        string            `yaml:"address"` // InternalIP | ExternalIP | Hostname
	Hosts          map[string]string `yaml:"hosts"`   // node name -> address override
	Nodes          []string          `yaml:"nodes"`   // only collect from these node names (empty = all)
	Bastion        string            `yaml:"bastion"` // user@host:port
	StrictHostKey  bool              `yaml:"strict_host_key"`
	// AcceptNewHostKeys records an unknown host's key in known_hosts on
	// first contact (StrictHostKeyChecking=accept-new). On by default: a
	// cluster is reached by node addresses nobody has ssh'd to by hand, and
	// refusing every first contact only teaches people to reach for
	// --insecure-host-key, which checks nothing ever again. A *changed*
	// key is still refused either way - that is the check that catches
	// something, and it is the one --insecure-host-key throws away.
	AcceptNewHostKeys bool   `yaml:"accept_new_host_keys"`
	KnownHosts        string `yaml:"known_hosts"`
	Concurrency       int    `yaml:"concurrency"`
	// Nice runs the probe scripts under renice 19 / ionice best-effort-lowest
	// so they yield to the node's workloads (see docs/PERFORMANCE.md).
	Nice bool `yaml:"nice"`
	// Backoff skips the next cycle for a node whose probe took longer than
	// half the refresh interval, or whose previous probe is still running,
	// instead of stacking sessions on a slow node.
	Backoff bool `yaml:"backoff"`
}

// AddFallbackHost makes host an SSH target when none are configured: the
// node a cluster was bootstrapped from is what khealth probes when the API
// server cannot list nodes (etcd down), so the etcd tab can still triage
// and restore. The entry is keyed by the host itself since the node name
// is unknown; it is never used while the API answers.
func (s *SSH) AddFallbackHost(host string) {
	if host == "" || len(s.Hosts) > 0 {
		return
	}
	name := host
	if h, _, err := net.SplitHostPort(host); err == nil {
		name = h
	}
	s.Hosts = map[string]string{name: host}
}

// Etcd configures etcd probing and backup expectations.
type Etcd struct {
	BackupDirs   []string      `yaml:"backup_dirs"`
	MaxBackupAge time.Duration `yaml:"max_backup_age"`
	Endpoint     string        `yaml:"endpoint"`
	CACert       string        `yaml:"ca_cert"`
	ClientCert   string        `yaml:"client_cert"`
	ClientKey    string        `yaml:"client_key"`
}

// Helm configures Helm release inspection and optional update checks.
type Helm struct {
	CheckUpdates bool              `yaml:"check_updates"`
	Repos        map[string]string `yaml:"repos"`          // name -> repo URL (index.yaml is fetched)
	UseHelmRepos bool              `yaml:"use_helm_repos"` // also consult the helm CLI's repositories.yaml (with its credentials)
	Timeout      time.Duration     `yaml:"timeout"`
}

// Logs configures journal collection on nodes.
type Logs struct {
	Lines int    `yaml:"lines"`
	Since string `yaml:"since"` // journalctl --since value, e.g. "-24h"
}

// Collect controls the demand tiers of the SSH collection. By default a
// tier is gathered only while the tab that shows it is open (at the
// heavy_every cadence), on R, and - for the journal - on a slow
// background floor so the log findings stay honest on the Overview.
type Collect struct {
	// Always pins tiers to every tab: journal | images | pv | config |
	// etcd-exec. [journal, images, pv, config, etcd-exec] is the pre-tab-driven
	// behaviour (every tier every heavy_every cycles on every tab).
	Always []string `yaml:"always"`
	// JournalBackground is the floor for the journal tier when no tab shows
	// it and it is not pinned; 0 disables the floor.
	JournalBackground time.Duration `yaml:"journal_background"`
}

// CollectTiers are the tier names collect.always accepts.
var CollectTiers = []string{"journal", "images", "pv", "config", "etcd-exec"}

// Thresholds hold the numeric limits used by the health checks.
type Thresholds struct {
	DiskWarnPct     int           `yaml:"disk_warn_pct"`
	DiskCritPct     int           `yaml:"disk_crit_pct"`
	InodeWarnPct    int           `yaml:"inode_warn_pct"`
	MemWarnPct      int           `yaml:"mem_warn_pct"`
	MemCritPct      int           `yaml:"mem_crit_pct"`
	CPUWarnPct      int           `yaml:"cpu_warn_pct"`
	LoadPerCPUWarn  float64       `yaml:"load_per_cpu_warn"`
	RestartWarn     int32         `yaml:"restart_warn"`
	PendingPodAge   time.Duration `yaml:"pending_pod_age"`
	CertExpiryWarn  time.Duration `yaml:"cert_expiry_warn"`
	ClockSkewWarn   time.Duration `yaml:"clock_skew_warn"`
	EtcdDBWarnPct   int           `yaml:"etcd_db_warn_pct"`
	EtcdFsyncWarnMs float64       `yaml:"etcd_fsync_warn_ms"`
	EtcdFragWarnPct int           `yaml:"etcd_frag_warn_pct"`
	UnusedImagesGB  float64       `yaml:"unused_images_gb"`
}

// Default returns the built-in defaults.
func Default() Config {
	return Config{
		Refresh:    30 * time.Second,
		HeavyEvery: 6,
		Collect:    Collect{JournalBackground: time.Hour},
		SSH: SSH{
			Enabled:           true,
			Port:              22,
			Sudo:              true,
			Timeout:           20 * time.Second,
			Address:           "InternalIP",
			StrictHostKey:     true,
			AcceptNewHostKeys: true,
			Concurrency:       8,
			Nice:              true,
			Backoff:           true,
		},
		Perf:    Perf{WatchCache: true, Protobuf: true, DiscoveryTTL: 5 * time.Minute, ConfigzTTL: 10 * time.Minute, DeniedTTL: 10 * time.Minute},
		Etcd:    Etcd{MaxBackupAge: 24 * time.Hour},
		Helm:    Helm{CheckUpdates: true, UseHelmRepos: true, Timeout: 15 * time.Second},
		Logs:    Logs{Lines: 400, Since: "-24h"},
		Actions: Actions{Enabled: true, HelmBinary: "helm"},
		Thresholds: Thresholds{
			DiskWarnPct:     80,
			DiskCritPct:     90,
			InodeWarnPct:    80,
			MemWarnPct:      85,
			MemCritPct:      95,
			CPUWarnPct:      85,
			LoadPerCPUWarn:  2.0,
			RestartWarn:     5,
			PendingPodAge:   5 * time.Minute,
			CertExpiryWarn:  30 * 24 * time.Hour,
			ClockSkewWarn:   5 * time.Second,
			EtcdDBWarnPct:   80,
			EtcdFsyncWarnMs: 10,
			EtcdFragWarnPct: 50,
			UnusedImagesGB:  5,
		},
	}
}

// Version is set at build time via -ldflags "-X github.com/zlmitchell/khealth-tui/internal/config.Version=...".
var Version = "dev"

// Load builds the configuration from defaults, the config file and flags.
func Load(args []string) (Config, error) {
	cfg := Default()

	fs := flag.NewFlagSet("khealth", flag.ContinueOnError)
	var (
		cfgPath      = fs.String("config", "", "config file (default: $XDG_CONFIG_HOME/khealth/config.yaml or ./khealth.yaml)")
		kubeconfig   = fs.String("kubeconfig", "", "path to kubeconfig (default: $KUBECONFIG or ~/.kube/config)")
		kctx         = fs.String("context", "", "kubeconfig context to use")
		ns           = fs.String("n", "", "initial namespace filter (empty = all)")
		refresh      = fs.Duration("refresh", 0, "refresh interval")
		theme        = fs.String("theme", "", "color palette: auto (ask the terminal for its background), light or dark (also KHT_THEME; for terminals that do not answer, which read as dark)")
		sshUser      = fs.String("ssh-user", "", "SSH user for nodes")
		sshKey       = fs.String("ssh-key", "", "SSH private key file")
		sshPort      = fs.Int("ssh-port", 0, "SSH port")
		sshPass      = fs.String("ssh-password", "", "SSH password fallback (prefer --ask-pass or KHT_SSH_PASSWORD; also used for sudo)")
		askPass      = fs.Bool("ask-pass", false, "prompt for the SSH/sudo password at startup")
		sshAddr      = fs.String("ssh-address", "", "node address type: InternalIP, ExternalIP or Hostname")
		bastion      = fs.String("bastion", "", "SSH jump host (user@host[:port])")
		sshNodes     = fs.String("ssh-nodes", "", "comma-separated node names to collect from (default: all)")
		noSSH        = fs.Bool("no-ssh", false, "disable SSH collection")
		noSudo       = fs.Bool("no-sudo", false, "do not escalate privileges on nodes (same as --become none)")
		become       = fs.String("become", "", "privilege escalation on nodes: auto (sudo, dzdo, doas), sudo, dzdo, doas or none")
		insecureHK   = fs.Bool("insecure-host-key", false, "skip SSH host key verification")
		acceptNewHK  = fs.Bool("accept-new-host-keys", true, "record a node's host key in known_hosts on first contact instead of refusing it (like StrictHostKeyChecking=accept-new; a changed key still fails). --accept-new-host-keys=false refuses hosts the file does not already hold")
		helmUpdates  = fs.Bool("helm-updates", true, "check your helm repos / helm.repos for newer chart versions (--helm-updates=false to disable)")
		readOnly     = fs.Bool("read-only", false, "disable mutating actions (helm rollback/upgrade)")
		diag         = fs.Bool("diag", false, "run API/permission diagnostics (nodes/proxy, stats/summary, pods/exec, ...) and exit")
		perfLog      = fs.String("perf-log", "", "append one JSON line per refresh cycle with the tool's own footprint (remote CPU, API bytes, local CPU) to this file")
		exportDir    = fs.String("export-dir", "", "directory where 'e' writes the findings report as khealth-<context>-<timestamp>.json and .xlsx (default: current directory)")
		exportOut    = fs.String("export", "", "no TUI: run one collection cycle, write the findings report and exit; a directory gets khealth-<context>-<timestamp>.json + .xlsx, a path ending in .json or .xlsx that one file")
		exportScan   = fs.Bool("export-scan", false, "with --export: run the security scan too (STIG/CIS rules, OS STIG facts over SSH; one sheet per benchmark)")
		exportHeavy  = fs.Bool("export-heavy", false, "with --export: collect the heavy node tiers too (journal, images, registry pull dry run)")
		pprofAddr    = fs.String("pprof", "", "serve net/http/pprof on this address (e.g. 127.0.0.1:6060)")
		noNice       = fs.Bool("no-nice", false, "do not renice/ionice the probe scripts on the nodes")
		noBackoff    = fs.Bool("no-backoff", false, "do not skip cycles for nodes whose probes are slow or still running")
		noWatchCache = fs.Bool("no-watch-cache", false, "list with a quorum read (resourceVersion unset) instead of the apiserver watch cache")
		noProtobuf   = fs.Bool("no-protobuf", false, "use JSON instead of protobuf for typed API lists")
		bootstrap    = fs.String("bootstrap-kubeconfig", "", "comma-separated server node addresses: fetch the admin kubeconfig over SSH, point it at a VIP/DNS the apiserver cert is valid for, name the context after the cluster, write it under ~/.kube and use it")
		bootstrapOut = fs.String("bootstrap-out", "", "where --bootstrap-kubeconfig writes the file (default ~/.kube/khealth-<cluster>.yaml)")
		bootstrapNm  = fs.String("bootstrap-name", "", "cluster/context name for --bootstrap-kubeconfig (default: the endpoint DNS name, else the node hostname without its index; dots become dashes)")
		bootstrapFr  = fs.Bool("bootstrap-fresh", false, "bootstrap again even when a ~/.kube/khealth-*.yaml for the cluster exists and connects (a stale one is replaced anyway)")
		showVersion  = fs.Bool("version", false, "print version and exit")
		initConfig   = fs.Bool("init-config", false, "write the annotated example config to --config (default: the user config path) and exit; never overwrites")
		printConfig  = fs.Bool("print-config", false, "print the annotated example config to stdout and exit")
		completions  = &optionalString{}
		instCompl    = fs.Bool("install-completions", false, "write the completion stub where the shell looks for it and exit; --completions <shell> picks the shell")
	)
	fs.Var(completions, "completions", "print the shell completion stub and exit (bash, zsh or fish; default bash): eval \"$(khealth --completions)\"")
	loadedFlagSet = fs // for the completion tests; the completer is handed fs directly
	// The shell asks for candidates with `khealth __complete <cword> <words...>`.
	// Answered here, before parsing, because the words being completed are
	// not this program's own arguments - but fs is already fully registered,
	// so the flag list the completer sees is the real one.
	if len(args) > 0 && args[0] == completeCommand {
		for _, c := range completeArgs(fs, args[1:]) {
			fmt.Println(c)
		}
		os.Exit(0)
	}
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "khealth - Kubernetes / RKE2 cluster health TUI\n\nUsage: khealth [flags] [[user@]server-node ...]\n\n  With no kubeconfig, name a server node (e.g. khealth root@10.0.0.143): the admin kubeconfig is fetched over SSH,\n  written under ~/.kube and used. Same as --bootstrap-kubeconfig user@host.\n\n")
		fs.PrintDefaults()
		fmt.Fprintf(fs.Output(), "\nkhealth %s - created by Zach Mitchell. Press ? inside the TUI for the key reference.\n", Version)
	}
	// flags and positional [user@]host arguments may be mixed (khealth
	// root@10.0.0.1 --no-ssh): the flag package stops at the first
	// positional, so collect it and parse the rest again
	var positional []string
	for rest := args; ; {
		if err := fs.Parse(rest); err != nil {
			if errors.Is(err, flag.ErrHelp) {
				os.Exit(0)
			}
			return cfg, err
		}
		if fs.NArg() == 0 {
			break
		}
		a := fs.Arg(0)
		if strings.HasPrefix(a, "-") {
			return cfg, fmt.Errorf("unexpected argument %q", a)
		}
		positional = append(positional, a)
		rest = fs.Args()[1:]
	}
	if *showVersion {
		fmt.Println("khealth", Version)
		os.Exit(0)
	}
	if *printConfig {
		fmt.Print(ExampleConfig)
		os.Exit(0)
	}
	if completions.set || *instCompl {
		// `--completions zsh` leaves zsh as a positional argument (the flag
		// takes its value with =), so claim it rather than treat a shell
		// name as a node to bootstrap from
		shell := completions.value
		if shell == "" && len(positional) > 0 {
			// with --completions a positional can only be the shell, so a
			// name we do not know is a mistake, not a node to bootstrap from
			if !isShell(positional[0]) {
				return cfg, fmt.Errorf("no completion for %q (have %s)", positional[0], strings.Join(CompletionShells(), ", "))
			}
			shell, positional = positional[0], positional[1:]
		}
		if *instCompl {
			path, err := InstallCompletion(shell)
			if err != nil {
				return cfg, err
			}
			fmt.Println("wrote", path)
			fmt.Println("open a new shell to pick it up")
			os.Exit(0)
		}
		script, err := CompletionScript(shell)
		if err != nil {
			return cfg, err
		}
		fmt.Print(script)
		os.Exit(0)
	}
	if *initConfig {
		target, err := WriteExampleConfig(*cfgPath)
		if err != nil {
			return cfg, err
		}
		fmt.Println("wrote", target)
		fmt.Println("edit it, then run khealth (it is found automatically) or pass --config", target)
		os.Exit(0)
	}

	path, explicit := *cfgPath, *cfgPath != ""
	if !explicit {
		path = findConfigFile()
	}
	if path != "" {
		b, err := os.ReadFile(path)
		if err != nil {
			if explicit {
				return cfg, fmt.Errorf("read config %s: %w", path, err)
			}
		} else if err := yaml.Unmarshal(b, &cfg); err != nil {
			return cfg, fmt.Errorf("parse config %s: %w", path, err)
		}
	}

	cfg.Flags = map[string]bool{}
	fs.Visit(func(f *flag.Flag) {
		cfg.Flags[f.Name] = true
		switch f.Name {
		case "kubeconfig":
			cfg.Kubeconfig = *kubeconfig
		case "context":
			cfg.Context = *kctx
		case "n":
			cfg.Namespace = *ns
		case "refresh":
			cfg.Refresh = *refresh
		case "theme":
			cfg.Theme = *theme
		case "ssh-user":
			cfg.SSH.User = *sshUser
		case "ssh-key":
			cfg.SSH.Key = *sshKey
		case "ssh-port":
			cfg.SSH.Port = *sshPort
		case "ssh-password":
			cfg.SSH.Password = *sshPass
		case "ask-pass":
			cfg.SSH.AskPass = *askPass
		case "ssh-address":
			cfg.SSH.Address = *sshAddr
		case "bastion":
			cfg.SSH.Bastion = *bastion
		case "ssh-nodes":
			cfg.SSH.Nodes = nil
			for _, n := range strings.Split(*sshNodes, ",") {
				if n = strings.TrimSpace(n); n != "" {
					cfg.SSH.Nodes = append(cfg.SSH.Nodes, n)
				}
			}
		case "no-ssh":
			cfg.SSH.Enabled = !*noSSH
		case "no-sudo":
			cfg.SSH.Sudo = !*noSudo
		case "become":
			cfg.SSH.Become = *become
		case "insecure-host-key":
			cfg.SSH.StrictHostKey = !*insecureHK
		case "accept-new-host-keys":
			cfg.SSH.AcceptNewHostKeys = *acceptNewHK
		case "helm-updates":
			cfg.Helm.CheckUpdates = *helmUpdates
		case "read-only":
			cfg.Actions.Enabled = !*readOnly
		case "diag":
			cfg.Diag = *diag
		case "perf-log":
			cfg.Perf.Log = *perfLog
		case "export-dir":
			cfg.Export.Dir = *exportDir
		case "export":
			cfg.Export.Out = *exportOut
		case "export-scan":
			cfg.Export.Scan = *exportScan
		case "export-heavy":
			cfg.Export.Heavy = *exportHeavy
		case "pprof":
			cfg.Perf.Pprof = *pprofAddr
		case "no-nice":
			cfg.SSH.Nice = !*noNice
		case "no-backoff":
			cfg.SSH.Backoff = !*noBackoff
		case "no-watch-cache":
			cfg.Perf.WatchCache = !*noWatchCache
		case "no-protobuf":
			cfg.Perf.Protobuf = !*noProtobuf
		case "bootstrap-kubeconfig":
			for _, h := range strings.Split(*bootstrap, ",") {
				if h = strings.TrimSpace(h); h != "" {
					cfg.Bootstrap.Hosts = append(cfg.Bootstrap.Hosts, h)
				}
			}
		case "bootstrap-out":
			cfg.Bootstrap.Out = *bootstrapOut
		case "bootstrap-name":
			cfg.Bootstrap.Name = *bootstrapNm
		case "bootstrap-fresh":
			cfg.Bootstrap.Fresh = *bootstrapFr
		}
	})
	// positional [user@]host arguments are bootstrap hosts (khealth root@10.0.0.1)
	for _, a := range positional {
		if a = strings.TrimSpace(a); a != "" {
			cfg.Bootstrap.Hosts = append(cfg.Bootstrap.Hosts, a)
		}
	}
	// a user given as user@host is as explicit as --ssh-user: it wins over
	// the user remembered in a reused kubeconfig context
	for i, h := range cfg.Bootstrap.Hosts {
		if u, host, ok := strings.Cut(h, "@"); ok && u != "" && host != "" {
			cfg.SSH.User, cfg.Bootstrap.Hosts[i] = u, host
			cfg.Flags["ssh-user"] = true
		}
	}
	cfg.Bootstrap.Out = expand(cfg.Bootstrap.Out)

	cfg.Kubeconfig = expand(cfg.Kubeconfig)
	cfg.Perf.Log = expand(cfg.Perf.Log)
	cfg.SSH.Key = expand(cfg.SSH.Key)
	cfg.SSH.KnownHosts = expand(cfg.SSH.KnownHosts)
	if cfg.SSH.Password == "" {
		cfg.SSH.Password = os.Getenv("KHT_SSH_PASSWORD")
	}
	if cfg.SSH.User == "" {
		cfg.SSH.User = os.Getenv("USER")
		if cfg.SSH.User == "" {
			cfg.SSH.User = os.Getenv("USERNAME")
		}
	}
	// the terminal, not the cluster, decides the theme: an environment
	// variable set for one terminal wins over the config file
	if t := os.Getenv("KHT_THEME"); t != "" && !cfg.Flags["theme"] {
		cfg.Theme = t
	}
	cfg.Theme = strings.ToLower(strings.TrimSpace(cfg.Theme))
	switch cfg.Theme {
	case "":
		cfg.Theme = "auto"
	case "auto", "light", "dark":
	default:
		return cfg, fmt.Errorf("theme: %q is not auto, light or dark", cfg.Theme)
	}
	if cfg.Refresh < 5*time.Second {
		cfg.Refresh = 5 * time.Second
	}
	if cfg.HeavyEvery < 1 {
		cfg.HeavyEvery = 1
	}
	for i, t := range cfg.Collect.Always {
		t = strings.ToLower(strings.TrimSpace(t))
		known := false
		for _, k := range CollectTiers {
			if t == k {
				known = true
			}
		}
		if !known {
			return cfg, fmt.Errorf("collect.always: unknown tier %q (one of %s)", cfg.Collect.Always[i], strings.Join(CollectTiers, ", "))
		}
		cfg.Collect.Always[i] = t
	}
	cfg.SSH.Become = strings.ToLower(strings.TrimSpace(cfg.SSH.Become))
	switch cfg.SSH.Become {
	case "":
		cfg.SSH.Become = "auto"
	case "auto", "sudo", "dzdo", "doas", "none":
	default:
		return cfg, fmt.Errorf("ssh.become: %q is not auto, sudo, dzdo, doas or none", cfg.SSH.Become)
	}
	if !cfg.SSH.Sudo {
		cfg.SSH.Become = "none"
	}
	if cfg.SSH.BecomePassword == "" {
		cfg.SSH.BecomePassword = os.Getenv("KHT_BECOME_PASSWORD")
	}
	if cfg.SSH.Concurrency < 1 {
		cfg.SSH.Concurrency = 1
	}
	if cfg.Logs.Lines <= 0 {
		cfg.Logs.Lines = 400
	}
	if cfg.Logs.Since == "" {
		cfg.Logs.Since = "-24h"
	}
	if cfg.Helm.Timeout <= 0 {
		cfg.Helm.Timeout = 15 * time.Second
	}
	return cfg, nil
}

// ExampleConfig is the annotated configuration shipped in the binary
// (--print-config / --init-config).
//
//go:embed config.example.yaml
var ExampleConfig string

// DefaultConfigPath is where --init-config writes and the first user-level
// place the config is looked for: $XDG_CONFIG_HOME/khealth/config.yaml
// (%AppData%/khealth/config.yaml on Windows).
func DefaultConfigPath() (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		home, herr := os.UserHomeDir()
		if herr != nil {
			return "", err
		}
		dir = filepath.Join(home, ".config")
	}
	return filepath.Join(dir, "khealth", "config.yaml"), nil
}

// WriteExampleConfig writes ExampleConfig to path (or DefaultConfigPath when
// empty), creating parent directories and refusing to overwrite.
func WriteExampleConfig(path string) (string, error) {
	if path == "" {
		var err error
		if path, err = DefaultConfigPath(); err != nil {
			return "", err
		}
	}
	path = expand(path)
	if _, err := os.Stat(path); err == nil {
		return "", fmt.Errorf("%s already exists; edit it or pass --config <new path>", path)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return "", err
	}
	if err := os.WriteFile(path, []byte(ExampleConfig), 0o600); err != nil {
		return "", err
	}
	return path, nil
}

func findConfigFile() string {
	// working directory first (k8s-health-tui.yaml is the pre-1.0 name), then
	// the user-level file, then its pre-1.0 location so an existing setup keeps working
	candidates := []string{"khealth.yaml", "k8s-health-tui.yaml"}
	if dir, err := os.UserConfigDir(); err == nil {
		candidates = append(candidates, filepath.Join(dir, "khealth", "config.yaml"))
	}
	if home, err := os.UserHomeDir(); err == nil {
		candidates = append(candidates, filepath.Join(home, ".config", "khealth", "config.yaml"))
	}
	if dir, err := os.UserConfigDir(); err == nil {
		candidates = append(candidates, filepath.Join(dir, "k8s-health-tui", "config.yaml"))
	}
	for _, c := range candidates {
		if st, err := os.Stat(c); err == nil && !st.IsDir() {
			return c
		}
	}
	return ""
}

func expand(p string) string {
	if strings.HasPrefix(p, "~") {
		if home, err := os.UserHomeDir(); err == nil {
			return filepath.Join(home, p[1:])
		}
	}
	return p
}
