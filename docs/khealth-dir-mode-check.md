# Directory checked against a file mode (FILE_REGEX ignored)

Date: 2026-10-30. Status: fixed in the working tree, not committed.

## Symptom

On RHEL 9.6 nodes (`C:\tmp\khealth-3node-v2\after\after-hardening.md`) khealth reported:

| Rule | Heading (target) | Fix shown | Actual STIG intent |
|---|---|---|---|
| V-258171 | `/etc/audit/`, `/etc/audit/rules.d/` | `chmod 0600` | `auditd.conf`, `audit.rules`, `rules.d/*.rules` at 0600 or stricter |
| V-257999 | `/etc/ssh/sshd_config.d/` | `chmod 0700` **and** `chmod 0600` | directory 0700 (correct), drop-in files inside it 0600 |
| V-258001 | `/etc/ssh/` | `chmod 0644` | `/etc/ssh/*.pub` 0644 or stricter |

When someone applied `chmod 0600` to `/etc/audit` and `/etc/audit/rules.d`, the directories lost their execute bit. With SELinux enforcing, auditd then failed to start ("Error opening config file (Permission denied)", an AVC denial of `dac_override`/`dac_read_search` for `auditd_t`). Root can only get through a directory with no `x` bit by using `dac_override`, and the policy does not give that to auditd.

## Root cause: a khealth bug, not the upstream content

The embedded tables (`internal/stigdata/data/*.json.gz`, built from ComplianceAsCode) are correct. The ComplianceAsCode `file_permissions` template preprocesses `FILE_REGEX` into a **list parallel to `FILEPATH`**. When `FILE_REGEX` is set, the targets are the files inside the directory whose names match the regex, never the directory itself. Here is V-258171 from `rhel9.json.gz`:

```json
{"rule": "file_permissions_audit_configuration_stig", "template": "file_permissions",
 "params": {"FILEPATH": ["/etc/audit/", "/etc/audit/rules.d/"],
            "FILE_REGEX": ["^.*audit(\\.rules|d\\.conf)$", "^.*\\.rules$"],
            "FILEMODE": "0600", "IS_DIRECTORY": true, "RECURSIVE": false}}
```

V-257999 has three checks. Only two of them should produce findings:
- `file_permissions_sshd_config`: `/etc/ssh/sshd_config` 0600 (a file, correct).
- `directory_permissions_sshd_config_d`: `/etc/ssh/sshd_config.d/` 0700, with no `FILE_REGEX`. This genuinely targets the directory, and 0700 is the RHEL 9 default. It is correct.
- `file_permissions_sshd_drop_in_config`: `/etc/ssh/sshd_config.d/` 0600 with `FILE_REGEX: ["^.*$"]`. This targets the files in the directory. **khealth applied it to the directory.**

V-258001 is `file_permissions_sshd_pub_key`: `FILEPATH ["/etc/ssh/"]`, `FILE_REGEX ["^.*\\.pub$"]`, `FILEMODE 0644`. khealth applied it to the directory, which is where the "/etc/ssh at 0644" finding comes from.

khealth read the parameter with `Check.Str("FILE_REGEX")` (`internal/stigdata/stigdata.go`, `Str`). `Str` returns `""` for any value that is not a string, so the list form was always ignored. The table never contains `FILE_REGEX` as a plain string. The bug showed up in three places (line numbers are from HEAD):

1. **Evaluator.** `internal/stig/ostemplates.go:414`: `scanned := c.Bool("RECURSIVE") || c.Str("FILE_REGEX") != ""` was false. The check fell through to a `stat` of the directory (`STIGStat["/etc/audit"]`, mode 750) and compared it with 0600, so it reported FAIL.
2. **Probe.** `internal/stigdata/probe.go:162`: `regex := c.Str("FILE_REGEX")` was empty, so no find scan was generated and the directory went into the stat list. Even if the regex had been read, two more bugs were waiting:
   - `probe.go:168` set `-type d` whenever `IS_DIRECTORY` was true. That is wrong when `FILE_REGEX` is set, because the targets are then files.
   - The regex was spliced in as `'<fp>(^...$)'`, and an ERE `^` in the middle of a pattern never matches.
3. **Remediation text.** `internal/stig/checklist.go:376-378`: the "(files matching ...)" suffix also used `Str`, so it was always dropped. The suggestion became a bare `chmod 0600` listed under the directory heading. For `RECURSIVE` rules it became `chmod <mode> -R <dir>`, which sets an exact numeric mode on files and directories alike.

The worst case is Ubuntu `/var/log` with `RECURSIVE: "true"` and `FILE_REGEX: [".*"]` at 0640:
- The scan ran with `-type d`, so every directory under `/var/log` failed against 0640.
- The suggested fix was `chmod 0640 -R /var/log/`, which would make the whole log tree untraversable.

## Affected rules

These are the `file_permissions` checks where a mode with no execute bit was applied to a directory. They are the dangerous ones, because applying the fix locks the directory.

| Product | VID | CAC rule | Mode | Paths |
|---|---|---|---|---|
| rhel8 | V-230471 | file_permissions_audit_configuration_stig | 0600 | /etc/audit/, /etc/audit/rules.d/ |
| rhel8 | V-230286 | file_permissions_sshd_pub_key | 0644 | /etc/ssh/ |
| rhel9 | V-258171 | file_permissions_audit_configuration_stig | 0600 | /etc/audit/, /etc/audit/rules.d/ |
| rhel9 | V-257999 (check 2) | file_permissions_sshd_drop_in_config | 0600 | /etc/ssh/sshd_config.d/ |
| rhel9 | V-258001 | file_permissions_sshd_pub_key | 0644 | /etc/ssh/ |
| rhel10 | V-281101 | file_permissions_etc_audit_rulesd | 0600 | /etc/audit/rules.d/ |
| rhel10 | V-281253 | file_permissions_sshd_pub_key | 0644 | /etc/ssh/ |
| ubuntu2204 | V-260601 | file_permissions_etc_audit_rulesd | 0600 | /etc/audit/rules.d/ |
| ubuntu2204 | V-260489 | permissions_local_var_log (recursive) | 0640 | /var/log/ (all subdirs) |
| ubuntu2204 | V-260490 | file_permissions_system_journal (recursive) | 0640 | /run/log/journal/, /var/log/journal/ |
| ubuntu2404 | V-270775 | file_permissions_etc_audit_rulesd | 0600 | /etc/audit/rules.d/ |
| ubuntu2404 | V-270756 | file_permissions_var_log_stig (recursive) | 0640 | /var/log/ (all subdirs) |
| ubuntu2404 | V-270757 | file_permissions_system_journal (recursive) | 0640 | /run/log/journal/, /var/log/journal/ |

These checks were also mis-targeted, but they cannot lock a directory:
- `file_permissions_library_dirs` (mode 7755 with `.so` regex): the scan covered directories instead of `.so` files. Products: rhel8 V-230260, rhel9 V-257884, rhel10 V-281060, ubuntu2204 V-260487, ubuntu2404 V-270696.
- `file_owner` / `file_groupowner` checks with `FILE_REGEX`: they checked the directory's owner instead of the files' owner. This covers the `*_audit_configuration`, `*_sshd_drop_in_config`, `*_library_dirs` and `*_system_journal` checks on every product.

The checks without `FILE_REGEX` really do target the directory, and all of their modes keep the execute bit, so they are fine. They are `file_permissions_var_log` 0755, `directory_permissions_sshd_config_d` 0700, `dir_permissions_library_dirs` 7755, `dir_permissions_binary_dirs` 0755 and `dir_permissions_system_journal` 2750.

## Fix (implemented, uncommitted)

The correct behavior for a directory is to compare the files inside it and leave the directory's own mode alone. khealth should never derive a directory mode from a file mode.

- `internal/stigdata/stigdata.go`: added `Check.FileRegex(i)`. It returns the `FILE_REGEX` entry for the i-th `FILEPATH`; a single string, or a single-element list, applies to every path.
- `internal/stigdata/probe.go`: `fileScan` is now the exported `FileScan(c, i)`, and it uses `FileRegex(i)`:
  - Rules with a regex scan `-type f`.
  - Rules that are `RECURSIVE` with no regex and `IS_DIRECTORY` scan `-type d`.
  - The regex is stripped of `^`/`$` and anchored as `'<dir>/(<re>)'`.
  - `Derive` passes the path index into `FileScan`.

  For example, the probe now emits:

  ```
  find '/etc/audit/rules.d' -xdev -maxdepth 1 -type f -regextype posix-extended -regex '/etc/audit/rules.d/(.*\.rules)' -perm /7177
  ```
- `internal/stig/ostemplates.go` (`fileCheck`): "scanned" is now decided per path (`RECURSIVE || FileRegex(i) != ""`). Paths handled by a scan are judged only by the probe's VIOL lines and are never stat'ed.
- `internal/stig/checklist.go` (`checkTargets`): scanned paths get a find-based fix that touches only the matched objects. Each fix uses a symbolic chmod that removes the excess bits (`stripModeBits`), matching the "this mode or stricter" semantics instead of a numeric `chmod -R`. For example:

  ```
  find /etc/audit/rules.d -xdev -maxdepth 1 -type f -regextype posix-extended -regex '/etc/audit/rules.d/(.*\.rules)' -perm /7177 -exec chmod u-xs,g-rwxs,o-rwxt {} +
  ```

  Plain file paths keep `chmod <mode>`.
- Tests in `internal/stig/dirmode_test.go`:
  - V-258171 passes with 0750 directories and fails on a violating `audit.rules`.
  - V-258001 does not fail on `/etc/ssh` at 0755.
  - The `sshd_config.d` directory rule still stats the directory.
  - The scan expression and fix text are checked for the regex, recursive-directory and recursive-plus-regex cases.
  - `stripModeBits` is tested.
  - `TestNoDirectoryGetsFileMode` is a table-wide guard: no embedded `file_permissions` check may stat a directory against a mode that lacks owner `x`.

`go test ./internal/stig/... ./internal/stigdata/... ./internal/nodeinfo/...` passes. Two tests also fail on a clean HEAD on Windows, so they are not caused by this change: `internal/sshrun` `TestNewAuthSetup` and `internal/ui` `TestRescueTypedSnapshotPath`.

## Follow-ups

- Nodes need a fresh probe, because the probe script changed. A cached probe from before the fix has no VIOL lines for these scans, so the checks would read as Pass.
- On the RHEL 9 test hosts, restore the directories with `chmod 0750 /etc/audit /etc/audit/rules.d` (or `restorecon`/`rpm --setperms audit`). Restore `/etc/ssh` to 0755 if it was changed.
- Translating the regexes from Python to POSIX ERE is still an approximation. It is fine for every expression in the current tables (`.*`, `\.`, groups, alternation).
