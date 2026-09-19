#!/usr/bin/env python3
"""Generate internal/stig/data/<product>.json.gz from a DISA OS STIG XCCDF and
ComplianceAsCode.

For every rule in the DISA XCCDF (dl.dod.cyber.mil) the generator looks up the
STIG ID (RHEL-09-211010 ...) in ComplianceAsCode's controls file for the
product, loads the CAC rules behind it with CAC's own `ssg` loader (so Jinja
macros, product properties and template preprocessing resolve exactly as in
the upstream build), resolves the XCCDF variables the templates reference
(control/profile selection, else the variable's default) and writes:

  {
    "product": "rhel9", "name": "DISA RHEL 9 STIG", "version": "V2R9",
    "date": "01 Jul 2026", "cac": "<commit>", "rules": [
      {"vid": "V-258230", "stigid": "RHEL-09-671010", "cat": "I",
       "title": "...", "check": "...", "fix": "...",
       "checks": [{"rule": "enable_fips_mode", "template": "sysctl",
                   "params": {"SYSCTLVAR": "...", ...}}],
       "status": "automated"}
    ]
  }

Rules whose CAC checks have no template (custom OVAL) get an empty template
and are reported as MANUAL by the engine unless a hand-written evaluator
exists for their vulnerability ID.

Usage (run inside a Linux checkout of ComplianceAsCode; see README.md):
  gen.py --cac /cac --xccdf U_RHEL_9_STIG_V2R9_Manual-xccdf.xml \
         --product rhel9 --controls /cac/products/rhel9/controls/stig_rhel9.yml \
         --name "DISA RHEL 9 STIG" --out rhel9.json.gz
"""
import argparse
import glob
import gzip
import json
import os
import re
import subprocess
import sys
import xml.etree.ElementTree as ET

import yaml

NS = {"x": "http://checklists.nist.gov/xccdf/1.1"}
SEVERITY = {"high": "I", "medium": "II", "low": "III"}

# preprocessed template parameters that name an XCCDF variable whose selected
# value the engine needs
VARIABLE_PARAMS = ("XCCDF_VARIABLE", "ARG_VARIABLE", "VARIABLE_NAME", "MOUNTOPTION_ARG_VAR", "EXT_VARIABLE", "VARIABLE")


def load_env(cac, product):
    sys.path.insert(0, cac)
    import ssg.environment  # noqa: E402

    cfg = os.path.join(cac, "build_config.gen.yml")
    with open(cfg, "w") as f:
        f.write('cmake_build_type: Release\nssg_version: [0, 1, 0]\nssg_version_str: "0.1.0"\n'
                'jinja2_cache_enabled: false\njinja2_cache_dir: ""\nsce_enabled: "false"\n')
    return ssg.environment.open_environment(cfg, os.path.join(cac, "products", product, "product.yml"),
                                            os.path.join(cac, "product_properties"))


def index_rules(cac):
    rules, variables = {}, {}
    for p in glob.glob(os.path.join(cac, "linux_os", "guide", "**", "rule.yml"), recursive=True):
        rules[os.path.basename(os.path.dirname(p))] = p
    for p in glob.glob(os.path.join(cac, "linux_os", "guide", "**", "*.var"), recursive=True):
        variables[os.path.basename(p)[:-4]] = p
    return rules, variables


def load_controls(path):
    doc = yaml.safe_load(open(path, encoding="utf-8"))
    out = {}
    for c in doc.get("controls", []):
        rules, sels = [], {}
        for r in c.get("rules") or []:
            r = str(r)
            if "=" in r:
                k, v = r.split("=", 1)
                sels[k] = v
            else:
                rules.append(r)
        out[c["id"]] = {"rules": rules, "selections": sels, "status": c.get("status", "")}
    return doc.get("version", ""), out


def load_profile_selections(cac, product):
    sels = {}
    for p in glob.glob(os.path.join(cac, "products", product, "profiles", "stig*.profile")):
        doc = yaml.safe_load(open(p, encoding="utf-8")) or {}
        for s in doc.get("selections") or []:
            s = str(s)
            if "=" in s and ":" not in s:
                k, v = s.split("=", 1)
                sels[k] = v
    return sels


class Resolver:
    def __init__(self, cac, env, variables):
        import ssg.build_yaml  # noqa: E402

        self.cac, self.env, self.variables, self.cache = cac, env, variables, {}
        self.Value = ssg.build_yaml.Value

    def value(self, name, selections):
        if name not in self.variables:
            return None
        if name not in self.cache:
            try:
                self.cache[name] = self.Value.from_yaml(self.variables[name], self.env)
            except Exception as e:  # pragma: no cover
                print("warn: variable", name, e, file=sys.stderr)
                self.cache[name] = None
        v = self.cache[name]
        if v is None:
            return None
        opts = v.options or {}
        sel = selections.get(name, "default")
        if sel in opts:
            return str(opts[sel])
        if "default" in opts:
            return str(opts["default"])
        return None


def clean(params):
    out = {}
    for k, v in params.items():
        if k.startswith("_"):
            continue
        if isinstance(v, (str, int, float, bool)):
            out[k] = v if isinstance(v, (str, bool)) else str(v)
        elif isinstance(v, (list, tuple)):
            out[k] = [clean(x) if isinstance(x, dict) else str(x) for x in v]
        elif isinstance(v, dict):
            out[k] = {str(a): (b if isinstance(b, (str, bool)) else str(b)) for a, b in v.items()}
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--cac", required=True)
    ap.add_argument("--xccdf", required=True)
    ap.add_argument("--product", required=True)
    ap.add_argument("--controls", default="", help="CAC controls file; omit when CAC has none (every rule is then manual)")
    ap.add_argument("--name", required=True)
    ap.add_argument("--out", required=True)
    a = ap.parse_args()

    env = load_env(a.cac, a.product)
    import ssg.build_yaml  # noqa: E402
    import ssg.templates  # noqa: E402

    rules_idx, vars_idx = index_rules(a.cac)
    ctl_version, controls = load_controls(a.controls) if a.controls else ("", {})
    profile_sels = load_profile_selections(a.cac, a.product)
    resolver = Resolver(a.cac, env, vars_idx)
    templates = {}

    def template(name):
        if name not in templates:
            templates[name] = ssg.templates.Template.load_template(os.path.join(a.cac, "shared", "templates"), name)
        return templates[name]

    commit = subprocess.run(["git", "-C", a.cac, "rev-parse", "--short", "HEAD"], capture_output=True, text=True).stdout.strip()
    root = ET.parse(a.xccdf).getroot()
    release = [p.text for p in root.findall("x:plain-text", NS) if p.get("id") == "release-info"][0]
    m = re.search(r"Release:\s*(\d+)\s+Benchmark Date:\s*(.+)$", release)
    version = "V%sR%s" % (root.find("x:version", NS).text.strip(), m.group(1))
    date = m.group(2).strip()

    out = {"product": a.product, "name": a.name, "version": version, "date": date, "cac": commit,
           "cac_controls_version": ctl_version, "rules": []}
    stats = {"rules": 0, "templated": 0, "custom": 0, "unmapped": 0}
    for g in root.findall("x:Group", NS):
        rule = g.find("x:Rule", NS)
        stigid = rule.find("x:version", NS).text.strip()
        vid = g.get("id")
        entry = {"vid": vid, "stigid": stigid, "cat": SEVERITY[rule.get("severity")],
                 "title": rule.find("x:title", NS).text.strip(),
                 "check": (rule.find("x:check/x:check-content", NS).text or "").strip(),
                 "fix": (rule.find("x:fixtext", NS).text or "").strip(),
                 "checks": [], "status": ""}
        stats["rules"] += 1
        ctl = controls.get(stigid)
        if not ctl or not ctl["rules"]:
            stats["unmapped"] += 1
            entry["status"] = (ctl or {}).get("status") or "unmapped"
            out["rules"].append(entry)
            continue
        entry["status"] = ctl["status"] or "automated"
        selections = dict(profile_sels)
        selections.update(ctl["selections"])
        for name in ctl["rules"]:
            if name not in rules_idx:
                entry["checks"].append({"rule": name, "template": "", "params": {}, "note": "not in guide"})
                continue
            try:
                r = ssg.build_yaml.Rule.from_yaml(rules_idx[name], env)
            except Exception as e:
                entry["checks"].append({"rule": name, "template": "", "params": {}, "note": "load error: %s" % e})
                continue
            chk = {"rule": name, "template": "", "params": {}}
            t = r.template
            if t and t.get("name"):
                tv = dict(t.get("vars") or {})
                tv["_rule_id"] = r.id_
                try:
                    params = template(t["name"]).preprocess(tv, "oval")
                except Exception as e:
                    params = {k.upper(): v for k, v in tv.items()}
                    chk["note"] = "preprocess: %s" % e
                chk["template"] = t["name"]
                chk["params"] = clean(params)
                # resolve XCCDF variables the template consumes
                resolved = {}
                if t["name"] == "sysctl" and not chk["params"].get("SYSCTLVAL"):
                    vn = "sysctl_%s_value" % chk["params"].get("SYSCTLID", "")
                    v = resolver.value(vn, selections)
                    if v is not None:
                        chk["params"]["SYSCTLVAL"] = v
                        resolved[vn] = v
                if t["name"] == "accounts_password" and chk["params"].get("VARIABLE"):
                    vn = "var_password_pam_" + chk["params"]["VARIABLE"]
                    v = resolver.value(vn, selections)
                    if v is not None:
                        resolved[vn] = v
                for pk in VARIABLE_PARAMS:
                    vn = chk["params"].get(pk)
                    if isinstance(vn, str) and vn and vn in vars_idx:
                        v = resolver.value(vn, selections)
                        if v is not None:
                            resolved[vn] = v
                if resolved:
                    chk["resolved"] = resolved
            entry["checks"].append(chk)
        if any(c["template"] for c in entry["checks"]):
            stats["templated"] += 1
        else:
            stats["custom"] += 1
        out["rules"].append(entry)

    with gzip.open(a.out, "wt", encoding="utf-8") as f:
        json.dump(out, f, indent=0, sort_keys=True)
    print("%s %s (%s): %d rules, %d templated, %d custom, %d unmapped -> %s" % (
        a.name, version, date, stats["rules"], stats["templated"], stats["custom"], stats["unmapped"], a.out))


if __name__ == "__main__":
    main()
