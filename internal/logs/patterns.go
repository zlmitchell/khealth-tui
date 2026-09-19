// Package logs classifies journal lines from rke2/k3s/kubelet/containerd
// into "normal during startup", "warning" and "error" with explanations so an
// operator can tell expected noise from real problems.
package logs

import (
	"regexp"
	"sort"
	"strings"
	"time"
)

// Class is the severity class of a matched line.
type Class int

const (
	ClassInfo    Class = iota // uninteresting / generic
	ClassStartup              // expected while a node is starting; a problem only if it persists
	ClassWarn
	ClassError
)

func (c Class) String() string {
	switch c {
	case ClassStartup:
		return "startup"
	case ClassWarn:
		return "warn"
	case ClassError:
		return "error"
	}
	return "info"
}

// Pattern is one knowledge-base entry.
type Pattern struct {
	Name    string
	Class   Class
	Re      *regexp.Regexp
	Explain string
	// Persist: if the pattern is still seen after the unit has been up this
	// long, escalate startup noise to a warning.
	Persist time.Duration
}

// Match is a classified log line.
type Match struct {
	Line    string
	Time    time.Time
	Unit    string
	Class   Class
	Pattern *Pattern
}

// Summary aggregates matches for one node.
type Summary struct {
	Total    int
	Counts   map[Class]int
	ByName   map[string]int
	Matches  []Match
	Startup  time.Time // rke2/k3s "up and running" marker, if seen
	LastLine time.Time
}

var patterns = []Pattern{
	// ---- completion markers ----
	{Name: "rke2-up", Class: ClassInfo, Re: regexp.MustCompile(`(rke2|k3s) is up and running`), Explain: "Startup completed: the supervisor finished bootstrapping."},
	{Name: "kubelet-started", Class: ClassInfo, Re: regexp.MustCompile(`Started kubelet|Starting kubelet`), Explain: "kubelet process launched."},

	// ---- normal startup noise (only a problem if it persists) ----
	{Name: "wait-apiserver", Class: ClassStartup, Re: regexp.MustCompile(`Waiting for API server to become available|Waiting to retrieve (kube-proxy|agent) configuration|Waiting for cloud-controller-manager privileges|Waiting for control-plane node .* startup`), Explain: "The supervisor is waiting for kube-apiserver / etcd. Normal for 30-120s after start; persistent = apiserver or etcd is not coming up (check etcd tab, container images, ports 6443/9345).", Persist: 5 * time.Minute},
	{Name: "wait-etcd", Class: ClassStartup, Re: regexp.MustCompile(`Waiting for etcd server to become available|Waiting for etcd (to become|cluster)`), Explain: "Waiting for the local etcd member. Normal during boot; persistent = etcd cannot start or cannot reach peers on 2380.", Persist: 5 * time.Minute},
	{Name: "conn-refused-local", Class: ClassStartup, Re: regexp.MustCompile(`dial tcp (127\.0\.0\.1|\[::1\]|localhost):(6443|2379|9345|10250|6444)[^\n]*connection refused`), Explain: "Local component not listening yet. Expected briefly at startup; persistent = the component (apiserver/etcd/kubelet) is failing.", Persist: 5 * time.Minute},
	{Name: "no-cni-yet", Class: ClassStartup, Re: regexp.MustCompile(`Container runtime network not ready|cni plugin not initialized|NetworkPluginNotReady`), Explain: "kubelet is up but the CNI has not written its config yet. Normal until the CNI daemonset starts; persistent = CNI pod failing (check kube-system canal/calico/cilium pods).", Persist: 5 * time.Minute},
	{Name: "node-not-found", Class: ClassStartup, Re: regexp.MustCompile(`nodes? "[^"]+" not found|Unable to register node|Attempting to register node`), Explain: "kubelet registering the node object. Normal on first join; persistent = kubelet cannot authenticate to the apiserver (token/cert) or the node was deleted.", Persist: 5 * time.Minute},
	{Name: "wait-supervisor", Class: ClassStartup, Re: regexp.MustCompile(`Waiting for .*supervisor|Failed to connect to proxy.*(9345|6443)|Remotedialer proxy error|Connecting to proxy`), Explain: "Agent (re)connecting to the rke2 supervisor websocket tunnel on 9345. Brief flaps are normal; persistent = server unreachable / firewall / wrong `server:` URL.", Persist: 5 * time.Minute},
	{Name: "image-pull-start", Class: ClassStartup, Re: regexp.MustCompile(`Pulling image|Importing images from|Imported images from`), Explain: "Loading airgap image tarballs or pulling system images. Normal; slow only on first boot or after upgrade."},
	{Name: "static-pod-wait", Class: ClassStartup, Re: regexp.MustCompile(`Pod for (etcd|kube-apiserver|kube-scheduler|kube-controller-manager|cloud-controller-manager) not synced|static pod .* not (yet )?(running|ready)`), Explain: "Static pod manifests written, waiting for containerd to start them. Normal for the first minute.", Persist: 5 * time.Minute},
	{Name: "temp-etcd", Class: ClassStartup, Re: regexp.MustCompile(`Starting temporary etcd|Reconciling bootstrap data|bootstrap data .* reconciled`), Explain: "Bootstrap reconciliation against the datastore. Normal on server start."},
	{Name: "wait-node-ready", Class: ClassStartup, Re: regexp.MustCompile(`Node .* not ready yet|node not ready|waiting for node`), Explain: "Waiting on node readiness. Normal for the first minutes.", Persist: 5 * time.Minute},
	{Name: "cert-rotate", Class: ClassInfo, Re: regexp.MustCompile(`certificate .* (renewed|rotated)|Rotating certificates|certificate is about to expire`), Explain: "Certificate rotation activity. rke2 rotates client certs on restart when within 90 days of expiry."},
	{Name: "defrag", Class: ClassInfo, Re: regexp.MustCompile(`Defragmenting etcd|defrag(ment)? (completed|finished|started)`), Explain: "rke2 defragments the local etcd member on startup. Normal."},
	{Name: "snapshot-ok", Class: ClassInfo, Re: regexp.MustCompile(`Saving etcd snapshot|Snapshot .* saved|etcd snapshot .* (complete|created)`), Explain: "Scheduled etcd snapshot ran."},

	// ---- warnings ----
	{Name: "etcd-slow-fsync", Class: ClassWarn, Re: regexp.MustCompile(`slow fdatasync|took too long|apply request took too long|waiting for ReadIndex response took too long|wal: sync duration`), Explain: "etcd disk latency. Sustained values mean the datastore disk is too slow (use SSD, isolate etcd from other IO)."},
	{Name: "leader-change", Class: ClassWarn, Re: regexp.MustCompile(`elected leader|lost leader|raft.node: .* (changed|lost) leader|became (leader|follower|candidate) at term`), Explain: "etcd leader election. Frequent elections indicate network or disk latency between control-plane nodes."},
	{Name: "s3-upload-fail", Class: ClassError, Re: regexp.MustCompile(`(?i)(failed|error|unable).{0,60}(upload|s3 client|s3 config|snapshot to s3|s3 bucket)|s3.{0,80}(AccessDenied|SignatureDoesNotMatch|NoSuchBucket|InvalidAccessKeyId|certificate signed by unknown authority|no such host|connection refused|RequestTimeTooSkewed)`), Explain: "etcd snapshot upload to S3 failed. Local snapshots continue; check etcd-s3-* settings (endpoint, bucket, credentials, CA) and that the bucket accepts writes."},
	{Name: "etcd-nospace", Class: ClassError, Re: regexp.MustCompile(`mvcc: database space exceeded|etcdserver: no space|alarm:NOSPACE|NOSPACE`), Explain: "etcd database hit its quota. Cluster is read-only until you compact, defrag and disarm the alarm."},
	{Name: "pleg", Class: ClassWarn, Re: regexp.MustCompile(`PLEG is not healthy|skipping pod synchronization`), Explain: "kubelet's pod lifecycle event generator is slow: containerd overloaded, too many containers, or disk IO issues. Node may flap NotReady."},
	{Name: "eviction", Class: ClassWarn, Re: regexp.MustCompile(`eviction manager|attempting to reclaim|Evicting pod|The node was low on resource`), Explain: "Node pressure (disk/memory/pid). kubelet is evicting pods. Check disk and memory usage on the Nodes tab."},
	{Name: "oom", Class: ClassWarn, Re: regexp.MustCompile(`Out of memory: Killed process|oom-kill|OOMKilling|OOMKilled`), Explain: "Kernel OOM killer fired. Check memory limits/requests and node memory."},
	{Name: "clock-skew", Class: ClassWarn, Re: regexp.MustCompile(`clock (skew|difference)|x509: certificate has expired or is not yet valid|time is (ahead|behind)`), Explain: "Clock skew or cert validity window. Ensure NTP/chrony is synchronized on all nodes."},
	{Name: "image-pull-fail", Class: ClassWarn, Re: regexp.MustCompile(`Failed to pull image|ErrImagePull|ImagePullBackOff|failed to resolve reference|pull access denied|failed to fetch anonymous token|manifest unknown`), Explain: "Image pull failures: registry unreachable, wrong tag, missing credentials, or registries.yaml mirror misconfiguration (airgap)."},
	{Name: "registry-tls", Class: ClassWarn, Re: regexp.MustCompile(`x509: certificate signed by unknown authority.*registry|http: server gave HTTP response to HTTPS client|tls: failed to verify certificate`), Explain: "TLS problem reaching a registry. Configure the CA / insecure_skip_verify in registries.yaml (rke2) or containerd certs.d."},
	{Name: "kube-proxy-wait", Class: ClassWarn, Re: regexp.MustCompile(`kube-proxy.*(failed|error)|Failed to (list|watch) .*(Endpoint|Service)`), Explain: "kube-proxy cannot sync services; check kube-proxy pod and apiserver connectivity."},
	{Name: "dns-fail", Class: ClassWarn, Re: regexp.MustCompile(`no such host|lookup .* on .*: (read udp|server misbehaving)|NXDOMAIN`), Explain: "DNS resolution failure from the node. Check /etc/resolv.conf and upstream DNS."},
	{Name: "unit-restart", Class: ClassWarn, Re: regexp.MustCompile(`Scheduled restart job|Main process exited, code=exited, status=[1-9]|Failed with result 'exit-code'`), Explain: "systemd restarted the service after a failure. Look at the lines just before this for the actual error."},
	{Name: "throttling", Class: ClassWarn, Re: regexp.MustCompile(`Waited for .*due to client-side throttling|rate limited|Throttling request took`), Explain: "Client-side API throttling. Usually harmless; if persistent the apiserver is overloaded."},
	{Name: "readiness-fail", Class: ClassWarn, Re: regexp.MustCompile(`(Readiness|Liveness) probe failed|probe .* failed`), Explain: "Pod probes failing on this node."},
	{Name: "volume-fail", Class: ClassWarn, Re: regexp.MustCompile(`MountVolume\.SetUp failed|Unable to attach or mount volumes|FailedMount|timed out waiting for the condition.*volume|orphaned pod`), Explain: "Volume mount problems: CSI driver, storage backend or orphaned pod directories."},
	{Name: "inotify", Class: ClassWarn, Re: regexp.MustCompile(`too many open files|inotify_add_watch|no space left on device.*inotify`), Explain: "fs.inotify limits reached. Raise fs.inotify.max_user_instances / max_user_watches."},
	{Name: "generic-warn", Class: ClassWarn, Re: regexp.MustCompile(`level=warn(ing)?|\bW[0-9]{4} `), Explain: "Warning-level log line not matched by a specific rule."},

	// ---- errors ----
	{Name: "token-mismatch", Class: ClassError, Re: regexp.MustCompile(`token does not match|Failed to validate token|bootstrap data already found and encrypted with different token|invalid bearer token|Unauthorized`), Explain: "Join token mismatch: the node's `token:` does not match the server's /var/lib/rancher/rke2/server/token (or the cluster was re-initialised). Fix the token in config.yaml."},
	{Name: "ca-mismatch", Class: ClassError, Re: regexp.MustCompile(`failed to get CA certs|certificate signed by unknown authority|x509: certificate is valid for|certificate verify failed`), Explain: "TLS trust failure between agent and server. Usually a rebuilt server with a new CA, a `server:` URL pointing at a different cluster, or a proxy intercepting TLS."},
	{Name: "cluster-id", Class: ClassError, Re: regexp.MustCompile(`cluster ID mismatch|cluster-id mismatch|member .* has already been bootstrapped|etcd cluster join failed|failed to join etcd cluster`), Explain: "This etcd member's data belongs to a different cluster. Remove the node from the cluster and wipe /var/lib/rancher/rke2/server/db before rejoining."},
	{Name: "etcd-member-missing", Class: ClassError, Re: regexp.MustCompile(`unable to find etcd member|etcdserver: member not found|etcd member .* is not in cluster|failed to (add|remove) member`), Explain: "etcd membership is out of sync with the nodes (stale member after a node was removed). Use etcdctl member list / member remove."},
	{Name: "port-in-use", Class: ClassError, Re: regexp.MustCompile(`address already in use|bind: address already in use`), Explain: "A required port (6443, 9345, 2379/2380, 10250) is taken by another process."},
	{Name: "disk-full", Class: ClassError, Re: regexp.MustCompile(`no space left on device`), Explain: "Filesystem is full. Check the Nodes tab disk usage (containerd images, logs, etcd)."},
	{Name: "containerd-down", Class: ClassError, Re: regexp.MustCompile(`Failed to start containerd|containerd.*(failed to start|exited)|failed to (connect|dial) .*containerd\.sock|failed to get sandbox image`), Explain: "Container runtime failure. Nothing can start until containerd is healthy (check /var/lib/rancher/rke2/agent/containerd/containerd.log)."},
	{Name: "kubelet-exit", Class: ClassError, Re: regexp.MustCompile(`kubelet exited|kubelet .* exited: exit status|Failed to start ContainerManager|failed to run Kubelet`), Explain: "kubelet crashed. Common causes: swap enabled, cgroup driver mismatch, protect-kernel-defaults with wrong sysctls, invalid kubelet args."},
	{Name: "swap", Class: ClassError, Re: regexp.MustCompile(`running with swap on is not supported|failSwapOn`), Explain: "kubelet refuses to run with swap enabled. Disable swap or set failSwapOn=false."},
	{Name: "kernel-defaults", Class: ClassError, Re: regexp.MustCompile(`protect-kernel-defaults|kernel defaults|invalid kernel flag|vm.overcommit_memory|kernel.panic`), Explain: "kubelet --protect-kernel-defaults is on but sysctls do not match (vm.overcommit_memory=1, vm.panic_on_oom=0, kernel.panic=10, kernel.panic_on_oops=1, kernel.keys.root_maxbytes/root_maxkeys). Apply rke2's rke2-cis-sysctl.conf."},
	{Name: "etcd-user", Class: ClassError, Re: regexp.MustCompile(`etcd user .* (does not exist|not found)|profile.*cis.*etcd`), Explain: "CIS profile requires an `etcd` user/group on the host: useradd -r -c 'etcd user' -s /sbin/nologin -M etcd -U."},
	{Name: "cis-precheck", Class: ClassError, Re: regexp.MustCompile(`CIS profile|host is not configured|failed CIS`), Explain: "CIS/STIG profile pre-flight check failed (sysctls, etcd user, or file permissions)."},
	{Name: "selinux", Class: ClassWarn, Re: regexp.MustCompile(`SELinux .* (denied|denial)|avc:.*denied`), Explain: "SELinux denials. Install rke2-selinux / container-selinux, or check custom policies."},
	{Name: "dup-hostname", Class: ClassError, Re: regexp.MustCompile(`duplicate hostname|hostname .* already (exists|registered)|node with name .* already exists`), Explain: "Two nodes share a hostname; set node-name in config.yaml or fix hostnames."},
	{Name: "fatal", Class: ClassError, Re: regexp.MustCompile(`level=fatal|panic:|fatal error`), Explain: "Fatal error: the process aborted. Read the full line."},
	{Name: "generic-error", Class: ClassError, Re: regexp.MustCompile(`level=error|\bE[0-9]{4} |error=`), Explain: "Error-level log line not matched by a specific rule."},
}

// Patterns returns the knowledge base (read-only).
func Patterns() []Pattern { return patterns }

var journalTime = regexp.MustCompile(`^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}[+-]\d{2}:?\d{2}|\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z)\s+\S+\s+([^\[:\s]+)`)

// Classify runs every line through the knowledge base.
func Classify(lines []string, now time.Time) *Summary {
	s := &Summary{Counts: map[Class]int{}, ByName: map[string]int{}}
	for _, line := range lines {
		t := strings.TrimSpace(line)
		if t == "" {
			continue
		}
		s.Total++
		m := Match{Line: line, Class: ClassInfo}
		if g := journalTime.FindStringSubmatch(t); g != nil {
			m.Unit = g[2]
			ts := g[1]
			if len(ts) > 5 && ts[len(ts)-3] != ':' && ts[len(ts)-1] != 'Z' {
				ts = ts[:len(ts)-2] + ":" + ts[len(ts)-2:]
			}
			if pt, err := time.Parse(time.RFC3339, ts); err == nil {
				m.Time = pt
				if pt.After(s.LastLine) {
					s.LastLine = pt
				}
			}
		}
		for i := range patterns {
			p := &patterns[i]
			if p.Re.MatchString(t) {
				m.Pattern = p
				m.Class = p.Class
				if p.Name == "rke2-up" && m.Time.After(s.Startup) {
					s.Startup = m.Time
				}
				break
			}
		}
		if m.Pattern != nil {
			s.ByName[m.Pattern.Name]++
		}
		s.Counts[m.Class]++
		s.Matches = append(s.Matches, m)
	}
	// escalate persistent startup noise: seen after the "up and running" marker (or in the last 10 minutes when no marker)
	for i := range s.Matches {
		m := &s.Matches[i]
		if m.Class != ClassStartup || m.Pattern == nil || m.Pattern.Persist == 0 || m.Time.IsZero() {
			continue
		}
		ref := s.Startup
		if ref.IsZero() {
			ref = now.Add(-10 * time.Minute)
		}
		if m.Time.After(ref.Add(m.Pattern.Persist)) {
			m.Class = ClassWarn
			s.Counts[ClassStartup]--
			s.Counts[ClassWarn]++
		}
	}
	return s
}

// TopPatterns returns the most frequent named patterns of the given class.
func (s *Summary) TopPatterns(class Class, n int) []string {
	type kv struct {
		name string
		n    int
	}
	var list []kv
	seen := map[string]bool{}
	for _, m := range s.Matches {
		if m.Class == class && m.Pattern != nil && !seen[m.Pattern.Name] {
			seen[m.Pattern.Name] = true
			list = append(list, kv{m.Pattern.Name, s.ByName[m.Pattern.Name]})
		}
	}
	sort.Slice(list, func(i, j int) bool { return list[i].n > list[j].n })
	var out []string
	for i, e := range list {
		if i >= n {
			break
		}
		out = append(out, e.name)
	}
	return out
}

// Find returns the pattern by name.
func Find(name string) *Pattern {
	for i := range patterns {
		if patterns[i].Name == name {
			return &patterns[i]
		}
	}
	return nil
}
