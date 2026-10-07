# VGS ShellFirm Jamf packages

The approved release ships three separate installers. No home directories or
startup files are part of their payloads; activation runs After all packages.

| Package | Repository input | Managed payload | Receipt | Jamf priority |
| --- | --- | --- | --- | --- |
| Checks | `shellfirm/checks/*.yaml` | `checks/default-checks.yaml` | `io.vgs.shellfirm.checks` | 5 |
| Binary | Rust workspace and locked dependencies | `bin/shellfirm` | `io.vgs.shellfirm.binary` | 10 |
| Policy | Root `.shellfirm.yaml` | `policy/.shellfirm.yaml` | `io.vgs.shellfirm.policy` | 20 |

Jamf accepts priorities from 1 through 20, with lower numbers installed first.
The uploader validates all three priorities and their dependency order before its
first package API call. Invalid priorities stop the release before any package
record is created.

All payloads live below `/Library/Application Support/VGS/ShellFirm/`. The binary
also exposes the existing `/usr/local/bin/shellfirm` link.

## Loading rules

Jamf builds set `SHELLFIRM_MANAGED_CHECKS_PATH` **at compile time** to
`/Library/Application Support/VGS/ShellFirm/checks/default-checks.yaml`.
`shellfirm/build.rs` then writes an empty embedded catalog without reading the
checks directory. The deployed executable contains the engine and a fixed catalog
path, not the default YAML rules. Ordinary upstream/developer builds keep their
embedded defaults for compatibility.

The Checks package concatenates every default YAML file in sorted order into one
complete YAML catalog. This preserves the same rule IDs, groups and default group
filtering as the embedded build. The files such as `aws.yaml` remain separately
editable in Git. The root `.shellfirm.yaml` continues to supply the separate VGS
policy; it is not combined with the default catalog.

At runtime, ShellFirm verifies root ownership, no symlinks and no group/world
write access on the catalog and its three managed parent directories. Invalid
YAML/regexes, empty catalogs, duplicate IDs, missing files and insecure permissions
return an error with a nonzero exit. There is no empty/embedded/user-catalog
fallback. Existing Zsh/Bash hooks block checked commands on this nonzero result.
A user cannot redirect this loader by setting an environment variable at runtime.
This is an integrity guard, not protection from a root administrator or removal of
shell hooks.

Checks are cached per process. Each new shell check process reads the latest
catalog; long-running MCP/wrapper/TUI processes must be restarted after an update.
Replacing only the catalog changes evaluated rules without rebuilding the engine.
The coordinated release workflow currently rebuilds and publishes **all three**
installers together; selective binary reuse is not implemented.

## Build, publish and deploy

The three `jamf-binary.yml`, `jamf-checks.yml` and `jamf-policy.yml` workflows build
individual packages on PRs/main and offer manual approval-gated upload. Each
artifact contains a package, manifest, checksum and build-environment information.
Bump the affected independent version in `versions.json` before a new manual
upload. These upload-only workflows do not change a Jamf policy.

`jamf-release.yml` coordinates deployment after a successful Tests push on main:
validate sources, build all three installers, wait for the existing `jamf`
environment approval, upload new package records, then create release-specific
policies for IT Security group 259. It verifies matching package kinds, commits,
versions and payload hashes before promotion. See [release details](release/README.md).
The release workflow assigns versions automatically.

Checks install before the managed binary, so the first transition does not leave
the new engine without its required catalog. The binary preinstall requires the
approved catalog hash; activation verifies the checks receipt/hash, the compiled
source path and actual loading as both root and the target user. It then performs
the existing VGS policy and shell-hook verification. The new health script records
four independent results: binary, VGS policy, user hooks, and default checks.

The approved-release descriptor uses schema 2 with a checks version/hash. Weekly
health still accepts schema 1 and the original embedded-check baseline, reporting
the separate-check result NOT_APPLICABLE for those versions. A malformed descriptor
fails verification. It never calls a changed YAML file evidence of user removal.

The first migration requires the new engine, default catalog and matching
activation/health scripts together. Do not deploy the new binary alone through
legacy policy 409. Subsequent checks-only package replacement is possible at
runtime, but must also update approved health expectations through the reviewed
release process. A manual package upload alone neither deploys nor updates those
expectations.

## Existing controls and recovery

Packages 1311/1312 are baselines, not overwrite targets. Every upload creates a new
versioned record; an identical READY/server-checksum record can be reused. No
package or script is deleted. Earlier installation/weekly policies are disabled
only during approved promotion, and the new installation policy is enabled last.

The existing GitHub `jamf` environment retains required review and main-only
access. `JAMF_URL` is a variable; `JAMF_CLIENT_ID` and `JAMF_CLIENT_SECRET` are secrets.
No new credentials or privileges are required for the third package. The current
API role has Read/Create/Update Packages and Policies, Read/Create Scripts and
Read Static Computer Groups. These privileges are tenant-wide; the workflow's
scope checks restrict this automation to group 259.

Use a new, explicitly scoped rollback policy with the previous package IDs and
matching activation/health expectations. An old once-per-computer policy does not
automatically run again. Rolling back to an embedded-check binary ignores the
remaining external catalog. Rolling back between managed releases must restore
matching checks and descriptor values. Endpoint success is confirmed in Jamf logs,
not by successful upload alone.

Packages remain unsigned pilot installers; the arm64 executable is ad-hoc signed.
Use standard Jamf computer policies, not PreStage/InstallEnterpriseApplication.
Developer ID signing and notarization are outside this change.

## Validation

```bash
python3 -m unittest discover -s packaging/jamf -p 'test_*.py' -v
cargo +stable test --locked --workspace
SHELLFIRM_MANAGED_CHECKS_PATH='/Library/Application Support/VGS/ShellFirm/checks/default-checks.yaml' cargo +stable build --locked --release --package shellfirm --bin shellfirm --target aarch64-apple-darwin
```

The builder validates both YAML formats with the compiled CLI, then expands each
PKG and verifies its exact single-file payload, checksum, receipt, permissions and
installer syntax. Python tests use fake APIs. The approved-release CI additionally
runs `verify_managed_runtime.py` on its ephemeral macOS runner: verify no embedded
AWS rule, change the catalog without changing the executable, confirm both the
new default rule and VGS policy work, and reject missing/corrupt/duplicate,
symlinked or writable catalogs. It never runs the test command itself.

Do not run that integration test on a workstation; it explicitly requires CI and
refuses an existing managed catalog. No installers or shell hooks are executed on
the developer workstation while preparing this PR. Live Jamf upload and endpoint
installation still require the approved pilot deployment.
