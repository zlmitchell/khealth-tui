// Package config holds the runtime configuration for khealth: defaults,
// the optional YAML config file and command-line flag overrides.
package config

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Config is the top-level configuration.
type Config struct {
	Kubeconfig string        `yaml:"kubeconfig"`
	Context    string        `yaml:"context"`
	Namespace  string        `yaml:"namespace"`
	Refresh    time.Duration `yaml:"refresh"`
	// HeavyEvery controls how often (in refresh cycles) the expensive SSH
	// collection (journal logs, image inventories, tarball manifests) runs.
	HeavyEvery int        `yaml:"heavy_every"`
	SSH        SSH        `yaml:"ssh"`
	Etcd       Etcd       `yaml:"etcd"`
	Helm       Helm       `yaml:"helm"`
	Logs       Logs       `yaml:"logs"`
	Actions    Actions    `yaml:"actions"`
	Thresholds Thresholds `yaml:"thresholds"`

	Diag bool `yaml:"-"` // --diag: print API/permission diagnostics and exit
}

// Actions configures the (opt-out) mutating operations run through CLIs.
type Actions struct {
	Enabled    bool   `yaml:"enabled"`
	HelmBinary string `yaml:"helm_binary"`
}

// SSH configures how nodes are reached over SSH.
type SSH struct {
	Enabled       bool              `yaml:"enabled"`
	User          string            `yaml:"user"`
	Key           string            `yaml:"key"`
	Password      string            `yaml:"password"` // fallback when public key auth fails (prefer --ask-pass / KHT_SSH_PASSWORD)
	AskPass       bool              `yaml:"ask_pass"` // prompt for the password at startup
	Port          int               `yaml:"port"`
	Sudo          bool              `yaml:"sudo"`
	Timeout       time.Duration     `yaml:"timeout"`
	Address       string            `yaml:"address"` // InternalIP | ExternalIP | Hostname
	Hosts         map[string]string `yaml:"hosts"`   // node name -> address override
	Nodes         []string          `yaml:"nodes"`   // only collect from these node names (empty = all)
	Bastion       string            `yaml:"bastion"` // user@host:port
	StrictHostKey bool              `yaml:"strict_host_key"`
	KnownHosts    string            `yaml:"known_hosts"`
	Concurrency   int               `yaml:"concurrency"`
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
	ArtifactHub  bool              `yaml:"artifacthub"`
	Repos        map[string]string `yaml:"repos"` // name -> repo URL (index.yaml is fetched)
	Timeout      time.Duration     `yaml:"timeout"`
}

// Logs configures journal collection on nodes.
type Logs struct {
	Lines int    `yaml:"lines"`
	Since string `yaml:"since"` // journalctl --since value, e.g. "-24h"
}

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
		SSH: SSH{
			Enabled:       true,
			Port:          22,
			Sudo:          true,
			Timeout:       20 * time.Second,
			Address:       "InternalIP",
			StrictHostKey: true,
			Concurrency:   8,
		},
		Etcd:    Etcd{MaxBackupAge: 24 * time.Hour},
		Helm:    Helm{Timeout: 15 * time.Second},
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

// Version is set at build time via -ldflags "-X k8s-health-tui/internal/config.Version=...".
var Version = "dev"

// Load builds the configuration from defaults, the config file and flags.
func Load(args []string) (Config, error) {
	cfg := Default()

	fs := flag.NewFlagSet("khealth", flag.ContinueOnError)
	var (
		cfgPath     = fs.String("config", "", "config file (default: $XDG_CONFIG_HOME/k8s-health-tui/config.yaml or ./k8s-health-tui.yaml)")
		kubeconfig  = fs.String("kubeconfig", "", "path to kubeconfig (default: $KUBECONFIG or ~/.kube/config)")
		kctx        = fs.String("context", "", "kubeconfig context to use")
		ns          = fs.String("n", "", "initial namespace filter (empty = all)")
		refresh     = fs.Duration("refresh", 0, "refresh interval")
		sshUser     = fs.String("ssh-user", "", "SSH user for nodes")
		sshKey      = fs.String("ssh-key", "", "SSH private key file")
		sshPort     = fs.Int("ssh-port", 0, "SSH port")
		sshPass     = fs.String("ssh-password", "", "SSH password fallback (prefer --ask-pass or KHT_SSH_PASSWORD; also used for sudo)")
		askPass     = fs.Bool("ask-pass", false, "prompt for the SSH/sudo password at startup")
		sshAddr     = fs.String("ssh-address", "", "node address type: InternalIP, ExternalIP or Hostname")
		bastion     = fs.String("bastion", "", "SSH jump host (user@host[:port])")
		sshNodes    = fs.String("ssh-nodes", "", "comma-separated node names to collect from (default: all)")
		noSSH       = fs.Bool("no-ssh", false, "disable SSH collection")
		noSudo      = fs.Bool("no-sudo", false, "do not use sudo on nodes")
		insecureHK  = fs.Bool("insecure-host-key", false, "skip SSH host key verification")
		helmUpdates = fs.Bool("helm-updates", false, "check Helm chart repos / Artifact Hub for newer chart versions")
		readOnly    = fs.Bool("read-only", false, "disable mutating actions (helm rollback/upgrade)")
		diag        = fs.Bool("diag", false, "run API/permission diagnostics (nodes/proxy, stats/summary, pods/exec, ...) and exit")
		showVersion = fs.Bool("version", false, "print version and exit")
	)
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "khealth - Kubernetes / RKE2 cluster health TUI\n\nUsage: khealth [flags]\n\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return cfg, err
	}
	if *showVersion {
		fmt.Println("khealth", Version)
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

	fs.Visit(func(f *flag.Flag) {
		switch f.Name {
		case "kubeconfig":
			cfg.Kubeconfig = *kubeconfig
		case "context":
			cfg.Context = *kctx
		case "n":
			cfg.Namespace = *ns
		case "refresh":
			cfg.Refresh = *refresh
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
		case "insecure-host-key":
			cfg.SSH.StrictHostKey = !*insecureHK
		case "helm-updates":
			cfg.Helm.CheckUpdates = *helmUpdates
		case "read-only":
			cfg.Actions.Enabled = !*readOnly
		case "diag":
			cfg.Diag = *diag
		}
	})

	cfg.Kubeconfig = expand(cfg.Kubeconfig)
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
	if cfg.Refresh < 5*time.Second {
		cfg.Refresh = 5 * time.Second
	}
	if cfg.HeavyEvery < 1 {
		cfg.HeavyEvery = 1
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

func findConfigFile() string {
	candidates := []string{"k8s-health-tui.yaml", "khealth.yaml"}
	if dir, err := os.UserConfigDir(); err == nil {
		candidates = append(candidates, filepath.Join(dir, "k8s-health-tui", "config.yaml"))
	}
	if home, err := os.UserHomeDir(); err == nil {
		candidates = append(candidates, filepath.Join(home, ".config", "k8s-health-tui", "config.yaml"))
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
