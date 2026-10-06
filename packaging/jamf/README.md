# VGS ShellFirm Jamf packages

Two GitHub Actions workflows build the successors to the current Jamf installers:

| Workflow | Input | Installed payload | Current baseline |
| --- | --- | --- | --- |
| Jamf Binary package | Rust workspace, `Cargo.lock`, `shellfirm/checks/*.yaml`, build scripts and default features | `/Library/Application Support/VGS/ShellFirm/bin/shellfirm` | Binary package 1311, receipt `io.vgs.shellfirm.binary` version `0.3.10.2` |
| Jamf Policy package | Repository root `.shellfirm.yaml` | `/Library/Application Support/VGS/ShellFirm/policy/.shellfirm.yaml` | Policy package 1312, receipt `io.vgs.shellfirm.policy` version `2026.08.1.1` |

`shellfirm/build.rs` embeds the default checks into the executable. Changing
`shellfirm/checks/aws.yaml` therefore requires a binary rebuild. The root VGS policy
remains a separate YAML payload and does not need to be embedded in the binary.
The policy workflow compiles ShellFirm to validate the YAML, but ships only the YAML.

The installers preserve the existing managed paths and command-link safeguards.
They do not overwrite an unrelated `/usr/local/bin/shellfirm` or an unowned policy
file. User symlinks and shell hooks remain the responsibility of the Jamf activation
script that runs **After** the packages. No home directories or shell profiles are
included in either package.

## Build and upload

1. Change the checks, Rust code, or root policy in a branch. Bump the affected
   installer version in `versions.json` before a new upload. Binary and policy
   versions are independent of the upstream application version in `Cargo.toml`.
   The initial successor versions are `0.3.10.3` and `2026.10.6.1`.
2. Open a PR. Both workflows run without Jamf secrets: Rust library tests,
   `cargo build --locked`, YAML validation, package creation and payload inspection.
   Dependencies come from `Cargo.lock`; the compiler uses the current stable Rust
   channel, and its version is recorded in `build-environment.txt`.
3. Review and merge. Changes to `main` build downloadable Actions artifacts. Each
   contains one `.pkg`, `manifest.json`, `SHA256SUMS` and build-environment details.
   Artifacts are retained for 30 days. Archive an approved release in the team's
   release storage before that period expires.
4. In **Actions**, choose **Jamf Binary package** or **Jamf Policy package**, then
   **Run workflow**, branch `main`, and enable `upload_to_jamf`. Review the `jamf`
   environment deployment request. This builds and uploads a candidate from that
   commit, then verifies Jamf reports `READY` and the same SHA-256.

Uploads create **new versioned package records**. IDs 1311 and 1312 are baselines,
not fixed destinations to overwrite. The job summary gives the new record ID.
Upload does not change a deployment policy, scope, script or endpoint.

The uploader accepts an existing filename only when its server checksum matches
and its transfer status is `READY`. A rebuild may produce different package bytes,
even for the same sources. In that case, bump the installer version before uploading
again. A failed upload leaves its newly created record for manual inspection;
the uploader never silently overwrites or deletes that record.

## One-time Jamf and GitHub setup

An administrator must create a dedicated Jamf **API Role** with only:

- Read Packages
- Create Packages
- Update Packages

Assign it to an enabled **API Client** with a short token lifetime (15 minutes is
sufficient for the upload job). A human console service account, SSO token, policy
write privilege or endpoint administrator password is not needed. Package privileges
are broader than this repository's files, so use this client only for this workflow.

Create a GitHub Actions environment named **`jamf`**, require an IT/Security reviewer,
and restrict its deployment branch to `main`. Configure:

| Type | Name | Value |
| --- | --- | --- |
| Environment variable | `JAMF_URL` | `https://getverygood.jamfcloud.com` |
| Environment variable, optional | `JAMF_CATEGORY_ID` | Numeric ID of the desired category; omitted means None (`-1`) |
| Environment secret | `JAMF_CLIENT_ID` | Dedicated API Client ID |
| Environment secret | `JAMF_CLIENT_SECRET` | Dedicated API Client secret |

Store credentials in GitHub environment secrets, never in Git or workflow inputs.
Require PR review for `main`, especially for workflows, packaging code and policy
changes. These controls must be configured in repository settings; the YAML does
not create required reviewers or branch protection. Build jobs have no Jamf secrets.
The upload job runs on a separate runner and consumes only this run's artifact.

The endpoints were checked against this tenant's Jamf Pro 11.32 API reference:
`POST /api/v1/oauth/token`, `GET/POST /api/v1/packages`,
`POST /api/v1/packages/{id}/upload` and `GET /api/v1/packages/{id}`.
The principal cloud distribution point must accept uploads. No separate JCDS/AWS
credentials are needed for this upload endpoint.

## Promote a candidate to the pilot

The current policy 409 installs the binary, then the policy, then runs activation
script 94. It executes **Once per computer**. Policy 410 runs weekly health-check
script 95. Merely uploading a package or changing policy 409's package list does
not make computers that have already completed it run again.

For each release, review the manifest's `promotion` values and create a release
canary policy with the new package IDs (binary priority 10, policy priority 20).
Use a release-specific trigger and an explicitly selected canary scope. Clone the
activation and health-check scripts for that release so the existing pilot remains
consistent during a staged rollout:

- Binary promotion: update activation's `expected_version` if the application
  version changes, and health check's binary receipt version.
- Policy promotion: update activation's `expected_policy_sha`, health check's
  `POLICY_SHA256`, and health check's policy receipt version.
- When promoting only one package, retain the other installed package's version
  and pins. Both candidates must come from a compatible reviewed release when
  promoting them together.
- Keep activation **After** the packages. Confirm its fixed Terragrunt rule probe
  remains valid if that rule changes. Confirm user symlink, policy readability,
  executable access and zsh/Bash hooks. Users need a new shell session for new hooks.
- Run the matching health check against canary endpoints. Keep the old and new
  health-check scopes disjoint during rollout, because they require exact versions.
  Promote beyond the canary only after install, activation and health-check logs pass.

For rollback, retain the previous package IDs and matching script revisions, and
run an explicit rollback policy on the affected scope. Do not assume an old
once-per-computer policy will rerun. This first CI/CD stage deliberately leaves
promotion and rollback under IT/Security control.

Packages remain **unsigned**, matching the reviewed pilot installers. The arm64
executable receives an ad-hoc signature after stripping, which is not Developer ID
signing or notarization. These packages are for standard Jamf computer policies;
do not use them for PreStage Enrollment or InstallEnterpriseApplication. Add the
team's Developer ID signing/notarization process before a rollout that requires it.

## Local validation

Use Python 3.11+ and an Apple Silicon Mac with Xcode command-line tools and Rust:

```bash
python3 -m unittest discover -s packaging/jamf -p 'test_*.py' -v
cargo +stable test --locked --workspace --lib
cargo +stable build --locked --release --package shellfirm --bin shellfirm --target aarch64-apple-darwin
strip target/aarch64-apple-darwin/release/shellfirm
codesign --force --sign - target/aarch64-apple-darwin/release/shellfirm
python3 packaging/jamf/build.py binary --binary target/aarch64-apple-darwin/release/shellfirm --output dist/binary --commit "$(git rev-parse HEAD)"
python3 packaging/jamf/build.py policy --binary target/aarch64-apple-darwin/release/shellfirm --output dist/policy --commit "$(git rev-parse HEAD)"
```

The builder expands each package and checks its receipt ID/version, installation
root, exact single-file payload, payload checksum, permissions and installer syntax.
It does not install packages or run their installer scripts on the build host.
Uploader tests use a fake API and never contact Jamf. A first authenticated upload
and canary installation are still required to validate the configured integration.

References: [Jamf client credentials](https://developer.jamf.com/jamf-pro/docs/client-credentials),
[package upload API](https://developer.jamf.com/jamf-pro/reference/post_v1-packages-id-upload),
[GitHub hosted macOS runners](https://docs.github.com/en/actions/reference/runners/github-hosted-runners).
