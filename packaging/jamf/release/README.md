# Approved IT Security pilot releases

The `jamf-release.yml` workflow publishes an approved three-package release after
a merge. The binary, checks and VGS policy workflows also validate individual
packages and support manual package upload without endpoint deployment.

## Release flow

1. An engineer changes default checks such as `shellfirm/checks/aws.yaml`, Rust
   source, or the separate root `.shellfirm.yaml`, and opens a PR.
2. PR validation compiles the binary, runs tests and strict Clippy, builds three
   installers, validates their payloads, and renders the activation/health scripts.
   No Jamf secrets are available to PR build jobs.
3. After merge to `main`, the existing **Tests** workflow must finish successfully.
   Its `workflow_run` event starts this release workflow for that exact commit.
   Failed tests and PR workflow events cannot start a deployment.
4. The workflow builds the Apple Silicon binary without embedded YAML checks,
   aggregates `shellfirm/checks/*.yaml` into a separate default-check catalog
   installer, and builds the separate VGS YAML installer. It stores all three with
   their release descriptor and activation scripts. The release currently builds
   and promotes all three together, including checks-only source changes.
5. **cyberleo17-VGS approves the `jamf` environment deployment.** Existing main-only
   restrictions, required review and disabled administrator bypass remain intact.
6. The deployment job verifies that the source commit is still the latest `main`,
   checks the tenant and pilot scope, uploads new package records, and waits for
   Jamf's READY state and matching server checksums. It never overwrites 1311/1312.
7. It creates immutable scripts and new disabled install/weekly-health policies,
   verifies their package/script IDs, triggers and group scope, and checks `main`
   again. It enables the new health policy, disables old pilot deployment/health
   policies, then enables the new installation policy last.
8. Jamf installs the default checks, binary, then VGS policy packages and runs activation After the
   packages. Installation is once per computer for each new release policy, at
   recurring check-in or configured login events, with three check-in retries.
   Login triggers depend on the tenant's login-event configuration. An eligible
   logged-in user is required for hook activation. Offline Macs wait for check-in.

A successful GitHub deployment means the verified Jamf policy is enabled. It does
not mean all endpoints installed successfully. Use that policy's Jamf logs for
installation, activation, and all four health results. GitHub records the new
policy, script and package IDs without publishing device inventory or credentials.

## Fixed scope and affected existing objects

`deployment.json` binds this workflow to `getverygood.jamfcloud.com` and static
computer group **259, IT Security**, observed with eight members on 2026-10-06.
Membership remains controlled in Jamf. There is no all-computers or arbitrary
policy-ID input. A mismatch in the baseline identities or scope stops promotion.

On the first approved release, policies **409** (baseline install) and **410**
(baseline weekly health) are disabled, not deleted. Their packages and scripts
**94/95** are preserved. Later releases also disable preceding policies matching
this workflow's exact naming convention and pilot scope. Old enabled installers
must be retired so a new group member cannot receive a later downgrade.

Generated names contain the workflow run, attempt and commit, for example:
`VGS ShellFirm CI r10.1 abcdef123456 - Install - IT Security`.
Each release has a new once-per-computer installation history. The weekly policy
runs once every week and continues to check Macs awaiting the new release.

## Versions and health checks

Application version comes from `shellfirm/Cargo.toml`. Installer versions are
assigned automatically and do not require editing `versions.json`:

- Binary: `<application version>.<1000 + run_number * 100 + run_attempt>`.
- Checks and VGS policy: `<UTC year>.<month>.<day>.<same sequence>`.

For example, application 0.3.10 in run 1, attempt 1 creates binary installer
0.3.10.1101. This does not change `shellfirm --version`. Full reruns have distinct
versions; rerunning only failed deployment jobs reuses the already-built artifact.
Versions are unique within this workflow; do not reset/recreate its run history or
reuse its version scheme in another release workflow. PR runs also consume numbers.

Activation verifies the exact compiled binary hash and version, the checks receipt
and catalog hash, root ownership, the fixed catalog source, runtime catalog loading
as root and as the selected user, VGS policy hash and syntax, policy discovery, the
existing Terragrunt test, and saved Zsh/Bash hooks.
It then atomically writes this non-secret root-owned descriptor:

`/Library/Application Support/VGS/ShellFirm/state/approved-release.plist`

The new weekly script remains read-only and checks:

1. Binary receipt version, executable, command link, and (for CI releases) hash.
2. Policy receipt version and policy file hash.
3. The selected user's managed policy link, access, and Zsh/Bash startup hooks.
4. Default-checks receipt version, catalog hash, ownership, and permissions.

Schema 2 descriptors include the checks package version and hash. Existing schema
1 releases and the pre-CI baseline retain their existing checks and report
`NOT_APPLICABLE` for the separate catalog. A malformed schema 2 descriptor fails.

The descriptor and its managed parent directories must be root-owned and not
writable by other users; the descriptor must be a regular 0644 file. A missing
descriptor uses only the reviewed baseline versions 0.3.10.2/2026.08.1.1. A malformed
or insecure descriptor fails checks rather than silently accepting the baseline.
The script does not source profiles or execute ShellFirm. It reports PASS/FAIL per
check and NOT_CHECKED when no eligible user is logged in. Missing files alone do
not prove a user removed them. This verifies installed release integrity and saved
hooks, not that a Mac is on the newest release or that existing terminals loaded
new hooks. Root-level tampering is outside this local health check's trust boundary.

The fixed activation probe still expects `vgs:terraform_apply_replace` to match
`terragrunt apply -replace=helm_release.flux`. If that policy is intentionally
changed, update the probe in the same reviewed PR.

## API permissions required before enabling this workflow

The existing package publisher role already has the required privileges:

- Read Policies, Create Policies, Update Policies
- Read Scripts, Create Scripts
- Read Static Computer Groups

Read/Create/Update Packages are also required. The third package needs no added privileges. No Delete privileges, Update Scripts,
MDM command privileges, console account, or new secrets are required. These API
privileges apply across their Jamf resource types; the code's group/object checks
are application safeguards, not a Jamf-enforced per-policy permission boundary.
Keep the token lifetime at 900 seconds. Changing privileges on the existing role
applies to newly issued tokens without rotating the stored secret.

Existing environment secrets: `JAMF_CLIENT_ID`, `JAMF_CLIENT_SECRET`.
Existing environment variable: `JAMF_URL`; optional `JAMF_CATEGORY_ID` is unchanged.
The built-in GitHub token only reads the latest main commit. No PAT is needed.
The GitHub deployment reviewer should inspect the candidate commit/version summary
before approval. Configure required PR checks/review on main separately; the
workflow does not create branch protection or prohibit direct pushes by itself.

## Failure, recovery, and rollback

All new policies are created disabled and read back before installation is enabled.
Failures never delete records or overwrite script contents. A failed upload can
leave an incomplete package record for inspection. If the filename conflicts,
review the record or rerun the full workflow to generate new installer versions.
For a failure after package upload, prefer **Re-run failed jobs**, which reuses the
same artifact and verified matching objects. Never approve an obsolete main commit.

An error between retirement and final activation can leave the old installation
policy disabled and the new installation policy disabled. Already installed
software continues running; the new health policy can still evaluate it. Inspect
the error and rerun failed jobs, or explicitly re-enable the last known-good policy.
There is no automatic rollback that could restore a policy an administrator changed.
Concurrent administrative edits are not transactional with this API; read-back and
scope rechecks detect common conflicts but cannot provide a distributed lock.

To roll back an installed release, disable the new installer, explicitly redeploy
known-good package IDs with their matching activation descriptor, and check the
endpoint logs. Re-enabling an old once-per-computer policy alone does not reinstall
it on computers with completed policy history. Returning all the way to the
pre-CI baseline requires removing the CI descriptor as part of the approved rollback
and restoring the matching baseline health policy. Retain previous packages and
scripts; release artifacts are retained for 90 days.

## Validation and remaining live verification

`python3 -m unittest discover -s packaging/jamf -p 'test_*.py' -v` tests artifact
integrity, scope rejection, immutable scripts, stale approvals, promotion ordering,
retirement and retry behavior against fake APIs. Build jobs additionally compile
and test Rust, inspect all three macOS packages, and check rendered shell syntax. They
also exercise the actual managed binary on an ephemeral GitHub macOS runner:
changing the catalog changes the matched rule without changing the executable,
while missing, malformed, insecure or symlinked catalogs fail. That fixture writes
only the managed catalog and its directories on the runner, then removes the
catalog; it does not run installers or destructive commands on an endpoint.

An authenticated upload and pilot installation remain to be verified after review,
merge and deployment approval. The Classic API resource routes were checked against
the tenant's 11.32 reference; live policy serialization/read-back is deliberately
checked before enabling an installation policy. Packages remain unsigned as in the
original pilot; this uses normal Jamf policies, not InstallEnterpriseApplication or
PreStage deployment.

References: [Jamf client credentials](https://developer.jamf.com/jamf-pro/docs/client-credentials),
[Classic API privilege mapping](https://developer.jamf.com/jamf-pro/docs/classic-api-minimum-required-privileges-and-endpoint-mapping).
