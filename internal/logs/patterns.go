// Package logs classifies journal lines from rke2/k3s/kubelet/containerd
// into "normal during startup", "warning" and "error" with explanations so an
// operator can tell expected noise from real problems.
package logs

import (
	"regexp"
	"sort"
	"strconv"
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
	Startup  time.Time   // rke2/k3s "up and running" marker, if seen
	Starts   []time.Time // start markers (rke2/k3s/kubelet/containerd starting), in order
	Ups      []time.Time // every "up and running" marker, in order
	LastLine time.Time
	Now      time.Time // when the window was collected
}

var patterns = []Pattern{
	// ---- completion markers ----
	{Name: "rke2-up", Class: ClassInfo, Re: regexp.MustCompile(`(rke2|k3s) is up and running`), Explain: "Startup completed: the supervisor finished bootstrapping."},
	{Name: "rke2-start", Class: ClassInfo, Re: regexp.MustCompile(`Starting (rke2|k3s) v|Starting rke2-(server|agent)|Started rke2-(server|agent)`), Explain: "The supervisor process started (boot, restart, upgrade). The minutes after it are the startup window: unmatched errors in it that do not recur are reported as startup noise."},
	{Name: "kubelet-started", Class: ClassInfo, Re: regexp.MustCompile(`Started kubelet|Starting kubelet|starting containerd`), Explain: "kubelet / containerd process launched."},

	// ---- rancher-system-agent (Rancher-provisioned downstream nodes) ----
	// Rancher delivers node config as plans; the agent rewrites
	// config.yaml.d/50-rancher.yaml, runs the installer and restarts rke2, so
	// these lines explain config changes that did not come from the node.
	{Name: "rancher-plan-failed", Class: ClassError, Re: regexp.MustCompile(`\[Applyinator\] .*finished with err: (exit status|signal|context)|\[Applyinator\] .*exit code: [1-9]|error (while )?applying plan|\[K8s\] error (while )?(applying|processing) (the )?plan`), Explain: "A Rancher plan step failed on this node (installer script, restart or one-time instruction). The node's config may be half-applied: compare config.yaml.d/50-rancher.yaml with the cluster (RKE2 tab) and read the command output in the full line."},
	{Name: "rancher-plan-applied", Class: ClassWarn, Re: regexp.MustCompile(`\[Applyinator\] Applying one-time instructions|Detected first start, force-applying one-time instruction set`), Explain: "Rancher applied a new plan on this node: config.yaml.d/50-rancher.yaml and the rke2 unit were (re)written and rke2 restarted. Expected after a Rancher-side change (upgrade, cluster config edit, registration); unexpected = Rancher's cluster spec differs from what the node ran before. The RKE2 tab shows drift between nodes."},
	{Name: "rancher-plan-received", Class: ClassInfo, Re: regexp.MustCompile(`\[K8s\] Processing secret .*machine-plan|\[K8s\] Received secret to process|\[K8s\] updated plan secret`), Explain: "rancher-system-agent received or acknowledged its plan secret from Rancher (fleet-default/*-machine-plan). Normal periodic traffic."},
	{Name: "rancher-plan-periodic", Class: ClassInfo, Re: regexp.MustCompile(`\[Applyinator\] Applying periodic instructions|\[Applyinator\] Running command|\[Applyinator\] Command .* finished with err: <nil>`), Explain: "Rancher's periodic plan instructions (etcd snapshot listing, cert checks) or a successful command. Normal."},
	{Name: "rancher-probe-fail", Class: ClassWarn, Re: regexp.MustCompile(`error while running probe|\[Prober\].*(fail|error)|probe (kubelet|kube-apiserver|kube-scheduler|kube-controller-manager|etcd|calico|canal|cilium) .*(fail|error)`), Explain: "A rancher-system-agent health probe (kubelet/apiserver/etcd/scheduler/controller-manager) is failing; Rancher will show the machine as unhealthy and may not proceed with plans. Check the component on this node."},
	{Name: "rancher-agent-start", Class: ClassInfo, Re: regexp.MustCompile(`Rancher System Agent version .* is starting`), Explain: "rancher-system-agent process started (boot, or Rancher upgraded the agent)."},
	{Name: "rancher-connect", Class: ClassStartup, Re: regexp.MustCompile(`error while connecting to Rancher|\[K8s\] error while (listing|watching)|Waiting for (Rancher|the cattle)|cattle-cluster-agent .*(error|failed)|rancher2_connection_info`), Explain: "rancher-system-agent (re)connecting to Rancher to fetch plans. Brief at start; persistent = the node cannot reach the Rancher URL (agent-url on the RKE2 tab): proxy, DNS, CA or the cattle-cluster-agent tunnel.", Persist: 5 * time.Minute},

	// ---- rke2 supervisor (rke2-server / rke2-agent journal) ----
	// The supervisor on 9345 fronts the embedded controllers and proxies
	// kubectl logs/exec and metrics traffic to the kubelets. Its errors at
	// boot are almost all "the thing behind me is not up yet"; the same
	// lines minutes after "up and running" point at what never came up.
	{Name: "supervisor-not-ready", Class: ClassStartup, Re: regexp.MustCompile(`runtime core not ready|Sending HTTP/1\.1 503 response`), Explain: "The supervisor's embedded controllers (the 'runtime core': node/etcd-member reconcilers, the kubelet proxy) are not running yet, so it answers 503 and cannot list the etcd nodes. Normal for the first minutes after rke2-server starts; persistent = the apiserver or etcd static pod never became ready: check the etcd tab and `crictl ps` on this node.", Persist: 5 * time.Minute},
	{Name: "supervisor-proxy-502", Class: ClassStartup, Re: regexp.MustCompile(`Sending HTTP/1\.1 502 response to .*(dial tcp [^ ]+:10250: (operation was canceled|connect: connection refused|i/o timeout)|context canceled|no such host)`), Explain: "The supervisor proxied a request (metrics-server scrape, kubectl logs/exec, the apiserver's egress tunnel) to a kubelet on 10250 that did not answer in time. Normal at boot while the kubelets and the tunnel come up; persistent = that node's kubelet is down or 10250 is blocked between the nodes (firewalld: open 10250/tcp for the node CIDR, or add the nodes to a trusted zone).", Persist: 5 * time.Minute},
	{Name: "supervisor-peer-down", Class: ClassStartup, Re: regexp.MustCompile(`Unable to reconcile with remote datastore.*(no route to host|connection refused|i/o timeout)|dial tcp [0-9.]+:9345: connect: (no route to host|connection refused|i/o timeout)`), Explain: "This server could not reach the server it joined through (the `server:` address in config.yaml, port 9345). When every node boots together the peers are simply not up yet; persistent = that node is down, 9345/tcp is blocked, or `server:` names a single node that no longer exists - point it at a VIP / load balancer (or at least a live server) so a restart does not depend on one peer.", Persist: 5 * time.Minute},
	{Name: "bootstrap-exists", Class: ClassInfo, Re: regexp.MustCompile(`Bootstrap key already exists`), Explain: "The restarting server found its bootstrap data already in the datastore. Normal on every restart of a joined server."},
	{Name: "supervisor-proxy-eof", Class: ClassInfo, Re: regexp.MustCompile(`Proxy error: (write|read) failed: .*(broken pipe|connection reset by peer|use of closed network connection)`), Explain: "A client of the supervisor's kubelet proxy closed the connection mid-response (a kubectl logs/exec session ended, a metrics scrape timed out). Harmless unless it repeats every scrape interval - then the kubelet on the target node is slow to answer."},
	{Name: "lease-lost", Class: ClassWarn, Re: regexp.MustCompile(`leaderelection lost|failed to renew lease|Error retrieving lease lock|error retrieving resource lock|failed to acquire lease`), Explain: "A control-plane component (kube-controller-manager, kube-scheduler, cloud-controller-manager, snapshot controller) could not renew its leader lease because the apiserver did not answer within the renew deadline; it exits and the kubelet restarts it (the restart counts on the Workloads tab). Causes: etcd disk latency (see etcd-slow-fsync), CPU steal on oversubscribed VMs, an apiserver restart. Fix the latency (SSD-backed etcd data dir, fewer vCPUs per host) or widen the tolerance in /etc/rancher/rke2/config.yaml: kube-controller-manager-arg / kube-scheduler-arg [leader-elect-lease-duration=60s, leader-elect-renew-deadline=40s, leader-elect-retry-period=10s]."},
	{Name: "kcm-early-start", Class: ClassStartup, Re: regexp.MustCompile(`unable to load configmap based request-header-client-ca-file`), Explain: "kube-controller-manager started before the local apiserver answered (it reads extension-apiserver-authentication at start) and exited; the kubelet restarts it. One or two per boot is normal; many means the apiserver is slow to come up on this node.", Persist: 5 * time.Minute},

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
	// kubelet restart races (kubelet.log / journal on rke2 nodes)
	{Name: "mirror-pod-exists", Class: ClassStartup, Re: regexp.MustCompile(`Failed creating a mirror pod.*already exists`), Explain: "The restarted kubelet tried to re-create the API mirror pods of its static pods (etcd, kube-apiserver, kube-scheduler, ...) that still exist from before the restart. Normal on every kubelet restart - one line per static pod, then the existing mirrors are adopted. Nothing to fix.", Persist: 5 * time.Minute},
	{Name: "container-gone", Class: ClassStartup, Re: regexp.MustCompile(`ContainerStatus from runtime service failed.*NotFound|failed to get container status.*not found|container .* not found: not found`), Explain: "The kubelet asked containerd about a container that was already removed (a pod restarted or was cleaned up meanwhile, typically right after a restart). Transient; persistent = kubelet and containerd disagree about what is running: compare `crictl ps -a` with the pods on this node and check containerd restarts.", Persist: 5 * time.Minute},
	{Name: "node-lease", Class: ClassStartup, Re: regexp.MustCompile(`Failed to update lease|failed to (update|renew) node lease|error updating node lease|Operation cannot be fulfilled on leases`), Explain: "The kubelet could not renew its node lease against the apiserver (127.0.0.1:6443 on a server, the supervisor tunnel on an agent). Normal while the apiserver starts or a conflicting update lands; persistent = the node goes NotReady after 40 s: apiserver down or overloaded, etcd latency (etcd-slow-fsync), or the tunnel to the servers is broken.", Persist: 3 * time.Minute},
	{Name: "orphaned-volumes-cleanup", Class: ClassInfo, Re: regexp.MustCompile(`Cleaned up orphaned pod volumes dir|Orphaned pod .* found, removing`), Explain: "The kubelet removed the volume directory of a pod that no longer exists (left behind by a restart or a force-deleted pod). Normal housekeeping."},
	{Name: "etcd-connect", Class: ClassStartup, Re: regexp.MustCompile(`Unable to connect to etcd: connection error|dial tcp [^ ]+:2379: connect: connection refused`), Explain: "The supervisor could not reach etcd on this node yet. Normal for the first minute after a server starts; persistent = the etcd static pod is not running (etcd tab, `crictl ps`) or 2379 is firewalled between the servers.", Persist: 5 * time.Minute},
	{Name: "wait-node-ready", Class: ClassStartup, Re: regexp.MustCompile(`Node .* not ready yet|node not ready|waiting for node`), Explain: "Waiting on node readiness. Normal for the first minutes.", Persist: 5 * time.Minute},
	{Name: "cert-rotate", Class: ClassInfo, Re: regexp.MustCompile(`certificate .* (renewed|rotated)|Rotating certificates|certificate is about to expire`), Explain: "Certificate rotation activity. rke2 rotates client certs on restart when within 90 days of expiry."},
	{Name: "defrag", Class: ClassInfo, Re: regexp.MustCompile(`Defragmenting etcd|defrag(ment)? (completed|finished|started)`), Explain: "rke2 defragments the local etcd member on startup. Normal."},
	{Name: "snapshot-ok", Class: ClassInfo, Re: regexp.MustCompile(`Saving etcd snapshot|Snapshot .* saved|etcd snapshot .* (complete|created)`), Explain: "Scheduled etcd snapshot ran."},

	// ---- warnings ----
	{Name: "etcd-slow-fsync", Class: ClassWarn, Re: regexp.MustCompile(`slow fdatasync|took too long|apply request took too long|waiting for ReadIndex response took too long|wal: sync duration`), Explain: "etcd disk latency: a WAL fsync or backend commit took longer than etcd expects (p99 should stay under 10 ms). Sustained values mean the datastore disk is too slow: put the data dir (/var/lib/rancher/rke2/server/db) on SSD/NVMe-backed storage with host cache off, keep etcd off disks shared with images and logs, and on VMs check CPU steal. As a stop-gap on a lab cluster raise etcd-arg [heartbeat-interval=500, election-timeout=5000] in config.yaml so the members stop losing leadership over it."},
	{Name: "leader-change", Class: ClassWarn, Re: regexp.MustCompile(`elected leader|lost leader|raft.node: .* (changed|lost) leader|became (leader|follower|candidate) at term`), Explain: "etcd leader election. Frequent elections indicate network or disk latency between control-plane nodes."},
	{Name: "s3-upload-fail", Class: ClassError, Re: regexp.MustCompile(`(?i)(failed|error|unable).{0,60}(upload|s3 client|s3 config|snapshot to s3|s3 bucket)|s3.{0,80}(AccessDenied|SignatureDoesNotMatch|NoSuchBucket|InvalidAccessKeyId|certificate signed by unknown authority|no such host|connection refused|RequestTimeTooSkewed)`), Explain: "etcd snapshot upload to S3 failed. Local snapshots continue; check etcd-s3-* settings (endpoint, bucket, credentials, CA) and that the bucket accepts writes."},
	{Name: "etcd-nospace", Class: ClassError, Re: regexp.MustCompile(`mvcc: database space exceeded|etcdserver: no space|alarm:NOSPACE|NOSPACE`), Explain: "etcd database hit its quota. Cluster is read-only until you compact, defrag and disarm the alarm."},
	{Name: "pleg", Class: ClassWarn, Re: regexp.MustCompile(`PLEG is not healthy|skipping pod synchronization`), Explain: "kubelet's pod lifecycle event generator is slow: containerd overloaded, too many containers, or disk IO issues. Node may flap NotReady."},
	{Name: "eviction", Class: ClassWarn, Re: regexp.MustCompile(`eviction manager|attempting to reclaim|Evicting pod|The node was low on resource`), Explain: "Node pressure (disk/memory/pid). kubelet is evicting pods. Check disk and memory usage on the Nodes tab."},
	{Name: "oom", Class: ClassWarn, Re: regexp.MustCompile(`Out of memory: Killed process|oom-kill|OOMKilling|OOMKilled`), Explain: "Kernel OOM killer fired. Check memory limits/requests and node memory."},
	{Name: "clock-skew", Class: ClassWarn, Re: regexp.MustCompile(`clock (skew|difference)|x509: certificate has expired or is not yet valid|time is (ahead|behind)`), Explain: "Clock skew or cert validity window. Ensure NTP/chrony is synchronized on all nodes."},
	{Name: "registry-auth", Class: ClassError, Re: regexp.MustCompile(`(failed to authorize|failed to fetch (anonymous|oauth) token|unexpected status( code)? from (GET|HEAD) request to [^ ]*: 401|401 Unauthorized|no basic auth credentials|pull access denied)`), Explain: "The registry rejected the pull as unauthenticated: the credentials in registries.yaml are wrong/rotated, or its configs key does not match the mirror endpoint host:port so containerd never sends them. The Nodes tab preflight probes each endpoint with the configured credentials."},
	{Name: "fapolicyd-deny", Class: ClassError, Re: regexp.MustCompile(`fork/exec [^ ]+: operation not permitted|fapolicyd.*(deny|denied)|dec=deny`), Explain: "fapolicyd (application allow-listing) blocked an exec. rke2 needs allow rules for its data-dir, /opt/cni, /run/k3s and /var/lib/kubelet (/etc/fapolicyd/rules.d/80-rke2.rules), and storage drivers for their host dirs (Longhorn /var/lib/longhorn). ausearch -m FANOTIFY -ts today -i shows what was denied."},
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
	{Name: "token-mismatch", Class: ClassError, Re: regexp.MustCompile(`token does not match|Failed to validate token|bootstrap data already found and encrypted with different token|invalid bearer token|Unauthorized`), Explain: "Join token mismatch: the node's `token:` does not match the server's /var/lib/rancher/rke2/server/token (or the cluster was re-initialized). Fix the token in config.yaml."},
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

// startupUnmatched replaces generic-error / generic-warn on lines logged
// inside a startup window that never recur outside one.
var startupUnmatched = Pattern{Name: "startup-unmatched", Class: ClassStartup, Explain: "An error-level line with no knowledge-base rule, logged while this node was starting (within 5 minutes of a start marker, or before the 'up and running' marker that followed it) and not seen again after: components racing each other - the kubelet before the apiserver answers, static pods before their mirror pods, controllers before the CNI is up. Nothing to fix unless the same message returns after startup; then read it for what could not be reached (an address, a lease, a container) and check that component."}

// startupWindowLen is how long after a start marker a node is "starting"
// when no "up and running" marker follows; startupSettle is the grace after
// the marker itself (mirror pods, leases and the CNI settle a while later).
const (
	startupWindowLen = 5 * time.Minute
	startupSettle    = 2 * time.Minute
)

// StartupWindows returns the periods this node was starting: from each
// start marker to the "up and running" marker that followed it plus a
// settle time, or startupWindowLen when none followed.
func (s *Summary) StartupWindows() [][2]time.Time {
	var out [][2]time.Time
	for _, st := range s.Starts {
		end := st.Add(startupWindowLen)
		for _, up := range s.Ups {
			if up.After(st) && up.Before(st.Add(2*startupWindowLen)) && up.Add(startupSettle).After(end) {
				end = up.Add(startupSettle)
			}
		}
		if n := len(out); n > 0 && !st.After(out[n-1][1]) {
			// overlapping starts (rke2 then kubelet then containerd): one window
			if end.After(out[n-1][1]) {
				out[n-1][1] = end
			}
			continue
		}
		out = append(out, [2]time.Time{st, end})
	}
	return out
}

// InStartup reports whether t falls in one of the node's startup windows.
func (s *Summary) InStartup(t time.Time) bool {
	if t.IsZero() {
		return false
	}
	for _, w := range s.StartupWindows() {
		if !t.Before(w[0]) && !t.After(w[1]) {
			return true
		}
	}
	return false
}

// demoteStartupNoise turns unmatched errors and warnings that only appear
// inside startup windows into startup noise: the operator wants to know
// whether an unexplained error is something to fix, and one that a restart
// produced and that never came back is not.
func (s *Summary) demoteStartupNoise() {
	windows := s.StartupWindows()
	if len(windows) == 0 {
		return
	}
	recurs := map[string]bool{}
	for i := range s.Matches {
		m := &s.Matches[i]
		if !isGeneric(m.Pattern) || m.Time.IsZero() || s.InStartup(m.Time) {
			continue
		}
		recurs[Signature(m.Line)] = true
	}
	for i := range s.Matches {
		m := &s.Matches[i]
		if !isGeneric(m.Pattern) || !s.InStartup(m.Time) || recurs[Signature(m.Line)] {
			continue
		}
		s.Counts[m.Class]--
		s.ByName[m.Pattern.Name]--
		m.Pattern, m.Class = &startupUnmatched, ClassStartup
		s.Counts[ClassStartup]++
		s.ByName[startupUnmatched.Name]++
	}
}

func isGeneric(p *Pattern) bool {
	return p != nil && (p.Name == "generic-error" || p.Name == "generic-warn")
}

var (
	sigQuoted = regexp.MustCompile(`"(?:[^"\\]|\\.)*"`)
	sigDigits = regexp.MustCompile(`[0-9]+`)
	sigKlog   = regexp.MustCompile(`^[IWEF]\d{4} \d\d:\d\d:\d\d\.\d+\s+\d+\s+`)
	sigLogfmt = regexp.MustCompile(`^time="[^"]*"\s*`)
)

// Signature is the shape of a log line with what varies between
// occurrences removed: prefixes, quoted strings and numbers. Two lines with
// the same signature are the same message about different objects.
func Signature(line string) string {
	t := strings.TrimSpace(line)
	if g := journalTime.FindStringIndex(t); g != nil {
		t = strings.TrimSpace(t[g[1]:])
		if i := strings.Index(t, ": "); i >= 0 && i < 12 {
			t = t[i+2:] // "[pid]: "
		}
	}
	t = sigKlog.ReplaceAllString(t, "")
	t = sigLogfmt.ReplaceAllString(t, "")
	t = sigQuoted.ReplaceAllString(t, `""`)
	t = sigDigits.ReplaceAllString(t, "#")
	if len(t) > 80 {
		t = t[:80]
	}
	return t
}

// Recurrence describes how often a line's message shape appears in the
// window: for the detail of an unmatched error, so the operator can tell a
// past incident from an ongoing one.
type Recurrence struct {
	Count       int
	First, Last time.Time
	Ongoing     bool // seen in the 10 minutes before the collection
}

// Recur counts the matches that share m's signature.
func (s *Summary) Recur(m Match) Recurrence {
	sig := Signature(m.Line)
	var r Recurrence
	for _, o := range s.Matches {
		if Signature(o.Line) != sig {
			continue
		}
		r.Count++
		if !o.Time.IsZero() {
			if r.First.IsZero() || o.Time.Before(r.First) {
				r.First = o.Time
			}
			if o.Time.After(r.Last) {
				r.Last = o.Time
			}
		}
	}
	r.Ongoing = !r.Last.IsZero() && r.Last.After(s.Now.Add(-10*time.Minute))
	return r
}

var journalTime = regexp.MustCompile(`^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}[+-]\d{2}:?\d{2}|\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z)\s+\S+\s+([^\[:\s]+)`)

// klogTime: "I0918 10:22:00.123456    1234 file.go:12] msg" (kubelet.log has no year)
var klogTime = regexp.MustCompile(`^[IWEF](\d{2})(\d{2}) (\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,9}))?\s`)

// logfmtTime: containerd.log lines start with time="RFC3339"
var logfmtTime = regexp.MustCompile(`^time="([^"]+)"`)

// Source is one stream of lines. The journal has Unit "" (each line carries
// its own unit); a log file such as rke2's kubelet.log names the unit it
// belongs to and carries klog/logfmt timestamps instead of the journal prefix.
type Source struct {
	Unit  string
	Lines []string
}

// Classify runs journal lines through the knowledge base.
func Classify(lines []string, now time.Time) *Summary {
	return ClassifySources([]Source{{Lines: lines}}, now)
}

// ClassifySources classifies several streams into one summary, ordered by
// time so file and journal lines interleave.
func ClassifySources(srcs []Source, now time.Time) *Summary {
	s := &Summary{Counts: map[Class]int{}, ByName: map[string]int{}, Now: now}
	for _, src := range srcs {
		for _, line := range src.Lines {
			t := strings.TrimSpace(line)
			if t == "" {
				continue
			}
			s.Total++
			m := Match{Line: line, Class: ClassInfo, Unit: src.Unit}
			if src.Unit == "" {
				if g := journalTime.FindStringSubmatch(t); g != nil {
					m.Unit = g[2]
					m.Time = parseISO(g[1])
				}
			} else {
				m.Time = fileTime(t, now)
			}
			if m.Time.After(s.LastLine) {
				s.LastLine = m.Time
			}
			s.classify(&m)
		}
	}
	if len(srcs) > 1 {
		sort.SliceStable(s.Matches, func(i, j int) bool {
			a, b := s.Matches[i].Time, s.Matches[j].Time
			return !a.IsZero() && !b.IsZero() && a.Before(b)
		})
	}
	s.escalate(now)
	s.demoteStartupNoise()
	return s
}

// parseISO reads a journalctl short-iso timestamp (offset may lack the colon).
func parseISO(ts string) time.Time {
	if len(ts) > 5 && ts[len(ts)-3] != ':' && ts[len(ts)-1] != 'Z' {
		ts = ts[:len(ts)-2] + ":" + ts[len(ts)-2:]
	}
	pt, err := time.Parse(time.RFC3339, ts)
	if err != nil {
		return time.Time{}
	}
	return pt
}

// fileTime reads a klog or logfmt timestamp from the start of a log-file line.
// klog has no year: assume the current one, unless that lands in the future.
func fileTime(t string, now time.Time) time.Time {
	if g := klogTime.FindStringSubmatch(t); g != nil {
		n := func(s string) int { v, _ := strconv.Atoi(s); return v }
		nanos := 0
		if g[6] != "" {
			nanos = n(g[6] + strings.Repeat("0", 9-len(g[6])))
		}
		pt := time.Date(now.Year(), time.Month(n(g[1])), n(g[2]), n(g[3]), n(g[4]), n(g[5]), nanos, now.Location())
		if pt.After(now.Add(24 * time.Hour)) {
			pt = pt.AddDate(-1, 0, 0)
		}
		return pt
	}
	if g := logfmtTime.FindStringSubmatch(t); g != nil {
		if pt, err := time.Parse(time.RFC3339Nano, g[1]); err == nil {
			return pt
		}
	}
	return time.Time{}
}

// classify matches one line against the knowledge base and records it.
func (s *Summary) classify(m *Match) {
	t := strings.TrimSpace(m.Line)
	for i := range patterns {
		p := &patterns[i]
		if p.Re.MatchString(t) {
			m.Pattern = p
			m.Class = p.Class
			switch p.Name {
			case "rke2-up":
				if m.Time.After(s.Startup) {
					s.Startup = m.Time
				}
				if !m.Time.IsZero() {
					s.Ups = append(s.Ups, m.Time)
				}
			case "rke2-start", "kubelet-started":
				if !m.Time.IsZero() {
					s.Starts = append(s.Starts, m.Time)
				}
			}
			break
		}
	}
	if m.Pattern != nil {
		s.ByName[m.Pattern.Name]++
	}
	s.Counts[m.Class]++
	s.Matches = append(s.Matches, *m)
}

// escalate turns persistent startup noise into warnings: seen after the "up
// and running" marker (or in the last 10 minutes when no marker).
func (s *Summary) escalate(now time.Time) {
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

// Last returns the newest match of a named pattern (zero Match when unseen).
func (s *Summary) Last(name string) Match {
	var last Match
	for _, m := range s.Matches {
		if m.Pattern != nil && m.Pattern.Name == name && !m.Time.Before(last.Time) {
			last = m
		}
	}
	return last
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
