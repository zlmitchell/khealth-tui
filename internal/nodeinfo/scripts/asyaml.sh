# Shared by every probe script (prepended by nodeinfo.Script and
# etcd.Script): the JSON-to-YAML step for Rancher-delivered files.
# Rancher-provisioned nodes get config.yaml.d/50-rancher.yaml and
# registries.yaml as one-line JSON. j2y turns JSON into block YAML (2-space
# indent, scalars kept quoted) so every reader here - mask, the data-dir
# and kubelet-arg lookups, the registries parser in preflight.sh, and the
# Go side - sees the one format. asyaml applies it when a file starts with
# "{" and passes YAML through untouched.
j2y() {
  awk '
  function pad(n,  s) { s=""; while (n-- > 0) s=s "  "; return s }
  function kq(k) { return (k ~ /^[A-Za-z0-9_.\/-]+$/) ? k : "\"" k "\"" }
  function place(txt) {
    if (typ[depth] == "[") print pad(depth-1) "- " txt
    else if (key != "") { print pad(depth-1) kq(key) ": " txt; key="" }
    else print txt
  }
  { s = s $0 "\n" }
  END {
    n=length(s); i=1; depth=0; key=""; pend=""
    while (i <= n) {
      c=substr(s,i,1)
      if (c ~ /[[:space:],]/) { i++; continue }
      if (c == "{" || c == "[") {
        if (typ[depth] == "[") print pad(depth-1) "-"
        else if (key != "") { print pad(depth-1) kq(key) ":"; key="" }
        depth++; typ[depth]=c; i++; continue
      }
      if (c == "}" || c == "]") { depth--; i++; continue }
      if (c == ":") { key=pend; pend=""; i++; continue }
      if (c == "\"") {
        j=i+1; str=""
        while (j <= n) { cj=substr(s,j,1); if (cj == "\\") { str=str cj substr(s,j+1,1); j+=2; continue }; if (cj == "\"") break; str=str cj; j++ }
        i=j+1
        if (typ[depth] == "{" && key == "") { pend=str; continue }
        place("\"" str "\""); continue
      }
      j=i; tok=""
      while (j <= n) { cj=substr(s,j,1); if (cj ~ /[],}[:space:]]/) break; tok=tok cj; j++ }
      i=j; place(tok)
    }
  }' "$1"
}
isjson() { head -c 64 "$1" 2>/dev/null | grep -q '^[[:space:]]*{'; }
asyaml() { if isjson "$1"; then j2y "$1"; else cat "$1"; fi; }
# jsonnote prints a comment line naming a file that is JSON on disk, so the
# dump says what it converted (every reader here skips comments)
jsonnote() { isjson "$1" && echo "# $1 is JSON on disk (Rancher-delivered), shown as YAML"; }
