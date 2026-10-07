#!/bin/zsh
set -eu
setopt pipefail

readonly managed_binary="/Library/Application Support/VGS/ShellFirm/bin/shellfirm"
readonly managed_policy="/Library/Application Support/VGS/ShellFirm/policy/.shellfirm.yaml"
readonly command_path="/usr/local/bin/shellfirm"
readonly managed_checks='/Library/Application Support/VGS/ShellFirm/checks/default-checks.yaml'
readonly expected_checks_sha='@CHECKS_SHA256@' 
readonly expected_version="shellfirm @APP_VERSION@"
readonly expected_policy_sha="@POLICY_SHA256@"

fail() {
  /bin/echo "VGS ShellFirm activation failed: $*" >&2
  exit 1
}

is_supported_user() {
  local candidate="${1:-}"
  local candidate_uid=""

  [[ -n "${candidate}" ]] || return 1
  [[ "${candidate}" != "root" && "${candidate}" != "loginwindow" && "${candidate}" != "_mbsetupuser" ]] || return 1
  candidate_uid="$(/usr/bin/id -u "${candidate}" 2>/dev/null)" || return 1
  (( candidate_uid >= 501 ))
}

run_as_target_user() {
  /bin/launchctl asuser "${target_uid}" \
    /usr/bin/sudo -u "${target_user}" \
    /usr/bin/env \
      HOME="${target_home}" \
      USER="${target_user}" \
      LOGNAME="${target_user}" \
      SHELL="${target_shell}" \
      PATH="/usr/local/bin:/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin" \
      "$@"
}

bash_profile_activates_bashrc() {
  local profile="${1}"

  [[ -f "${profile}" ]] || return 1
  /usr/bin/awk '
    /^[[:space:]]*#/ { next }
    /(^|[[:space:];&|])(source|\.)[[:space:]]+.*\.bashrc/ { found = 1 }
    END { exit(found ? 0 : 1) }
  ' "${profile}"
}

install_managed_policy_link() {
  local target_policy="${target_home}/.shellfirm.yaml"
  local current_sha=""
  local current_link=""

  if [[ -L "${target_policy}" ]]; then
    current_link="$(/usr/bin/readlink "${target_policy}")"
    [[ "${current_link}" == "${managed_policy}" ]] || \
      fail "${target_policy} points to an unmanaged policy (${current_link})."
  elif [[ -e "${target_policy}" ]]; then
    [[ -f "${target_policy}" ]] || fail "${target_policy} exists but is not a regular file."
    current_sha="$(/usr/bin/shasum -a 256 "${target_policy}" | /usr/bin/awk '{print $1}')"
    [[ "${current_sha}" == "${expected_policy_sha}" ]] || \
      fail "${target_policy} already exists with different content; it was preserved."

    /bin/echo "Replacing the matching policy copy at ${target_policy} with the managed policy link."
    /bin/rm -f "${target_policy}"
    /usr/bin/sudo -u "${target_user}" /bin/ln -s "${managed_policy}" "${target_policy}"
  else
    /usr/bin/sudo -u "${target_user}" /bin/ln -s "${managed_policy}" "${target_policy}"
  fi

  [[ -L "${target_policy}" ]] || fail "${target_policy} was not created as a symbolic link."
  [[ "$(/usr/bin/readlink "${target_policy}")" == "${managed_policy}" ]] || \
    fail "${target_policy} does not point to the VGS-managed policy."
}

[[ "$(/usr/bin/id -u)" == "0" ]] || fail "this script must run as root through Jamf Pro."

arm64_available="$(/usr/sbin/sysctl -n hw.optional.arm64 2>/dev/null)" || arm64_available="0"
[[ "${arm64_available}" == "1" ]] || fail "Apple Silicon (arm64) is required."

[[ -x "${managed_binary}" ]] || fail "${managed_binary} is missing or not executable."
[[ -x "${command_path}" ]] || fail "${command_path} is missing; install the current binary package first."
[[ -L "${command_path}" ]] || fail "${command_path} is not the VGS-managed symbolic link."
[[ "$(/usr/bin/readlink "${command_path}")" == "${managed_binary}" ]] || fail "${command_path} points to an unmanaged target."

[[ "$(/usr/bin/shasum -a 256 "${managed_binary}" | /usr/bin/awk '{print $1}')" == '@BINARY_SHA256@' ]] || fail "binary checksum differs from the approved artifact."
actual_version="$("${command_path}" --version 2>/dev/null)" || actual_version=""
[[ "${actual_version}" == "${expected_version}" ]] || fail "expected ${expected_version}, found ${actual_version:-unknown}."

[[ -f "${managed_policy}" && ! -L "${managed_policy}" ]] || \
  fail "${managed_policy} is missing or is not a regular managed file."
actual_policy_sha="$(/usr/bin/shasum -a 256 "${managed_policy}" | /usr/bin/awk '{print $1}')"
[[ "${actual_policy_sha}" == "${expected_policy_sha}" ]] || \
  fail "${managed_policy} does not match the approved policy SHA-256."
"${managed_binary}" policy validate "${managed_policy}" >/dev/null || \
  fail "${managed_policy} did not pass ShellFirm policy validation."

[[ -f "$managed_checks" && ! -L "$managed_checks" ]] || fail 'managed default checks are missing.'
[[ "$(/usr/bin/shasum -a 256 "$managed_checks" | /usr/bin/awk '{print $1}')" == "$expected_checks_sha" ]] || fail 'default checks checksum differs from the approved release.'
checks_receipt="$(/usr/sbin/pkgutil --pkg-info-plist io.vgs.shellfirm.checks)" || fail 'default-checks package receipt is missing.'
checks_version="$(/usr/bin/plutil -extract pkg-version raw -o - - <<< "$checks_receipt")" || fail 'cannot read default-checks version.'
[[ "$checks_version" == '@CHECKS_VERSION@' ]] || fail 'default-checks package version differs.'
[[ "$("$managed_binary" default-checks source)" == "$managed_checks" ]] || fail 'binary does not use the managed default-checks file.'
"$managed_binary" default-checks status || fail 'default-checks runtime validation failed.'

console_user="$(/usr/bin/stat -f '%Su' /dev/console 2>/dev/null)" || console_user=""
jamf_user="${3:-}"

if is_supported_user "${console_user}"; then
  readonly target_user="${console_user}"
elif is_supported_user "${jamf_user}"; then
  readonly target_user="${jamf_user}"
else
  fail "no logged-in human user was found. Run this policy at login."
fi

readonly target_uid="$(/usr/bin/id -u "${target_user}")"
home_record="$(/usr/bin/dscl . -read "/Users/${target_user}" NFSHomeDirectory 2>/dev/null)" || fail "cannot read the home directory for ${target_user}."
shell_record="$(/usr/bin/dscl . -read "/Users/${target_user}" UserShell 2>/dev/null)" || fail "cannot read the login shell for ${target_user}."
readonly target_home="${home_record#NFSHomeDirectory: }"
readonly target_shell="${shell_record#UserShell: }"

[[ "${target_home}" == /Users/* && -d "${target_home}" ]] || fail "refusing unexpected home directory ${target_home}."

/bin/echo "Activating ${expected_version} for ${target_user} (${target_home})."

install_managed_policy_link
run_as_target_user "$command_path" default-checks status || fail 'default checks are inaccessible to the user.'

run_as_target_user "${command_path}" policy validate "${target_home}/.shellfirm.yaml" >/dev/null || \
  fail "the user-visible VGS policy did not pass ShellFirm validation."

policy_status="$(run_as_target_user /bin/zsh -c 'cd -- "$HOME" && /usr/local/bin/shellfirm status' 2>&1)" || \
  fail "ShellFirm status failed while verifying project-policy discovery."
/bin/echo "${policy_status}"
/bin/echo "${policy_status}" | /usr/bin/grep -Eq '\.shellfirm\.yaml:[[:space:]]+found \(valid\)' || \
  fail "ShellFirm did not discover a valid .shellfirm.yaml from ${target_home}."

policy_rule_output="$(run_as_target_user /bin/zsh -c 'cd -- "$HOME" && /usr/local/bin/shellfirm pre-command --test -c "terragrunt apply -replace=helm_release.flux"' 2>&1)" || \
  fail "the VGS Terragrunt policy test returned an error."
/bin/echo "${policy_rule_output}"
/bin/echo "${policy_rule_output}" | /usr/bin/grep -Fq 'id: vgs:terraform_apply_replace' || \
  fail "the VGS Terragrunt apply -replace rule was not active."

# ShellFirm intentionally installs persistent hooks only when it has a TTY.
# Jamf scripts are non-interactive, so macOS `script` supplies a pseudo-TTY
# while the process still runs with the target user's identity and HOME.
run_as_target_user /usr/bin/script -q /dev/null "${command_path}" init

# ShellFirm writes Bash's hook to .bashrc. macOS Bash login shells normally
# read .bash_profile instead, so add the same official initialization line only
# when .bash_profile neither initializes ShellFirm nor sources .bashrc.
readonly bash_profile="${target_home}/.bash_profile"
if [[ ! -f "${bash_profile}" ]] || \
   { ! /usr/bin/grep -Fq 'shellfirm init bash' "${bash_profile}" 2>/dev/null && \
     ! bash_profile_activates_bashrc "${bash_profile}"; }; then
  /usr/bin/printf '\n# Added by VGS ShellFirm Jamf activation\neval "$(shellfirm init bash)"\n' | \
    /usr/bin/sudo -u "${target_user}" /usr/bin/tee -a "${bash_profile}" >/dev/null
fi

verification_output="$(run_as_target_user "${command_path}" init --dry-run 2>&1)" || fail "ShellFirm dry-run verification returned an error."
/bin/echo "${verification_output}"

/bin/echo "${verification_output}" | /usr/bin/grep -Eq 'zsh.*already installed' || fail "the Zsh hook was not verified."
/bin/echo "${verification_output}" | /usr/bin/grep -Eq 'bash.*already installed' || fail "the Bash hook was not verified."

/usr/bin/grep -Fq 'eval "$(shellfirm init zsh)"' "${target_home}/.zshrc" || fail "the Zsh startup file does not contain the ShellFirm hook."
/usr/bin/grep -Fq 'eval "$(shellfirm init bash)"' "${target_home}/.bashrc" || fail "the Bash startup file does not contain the ShellFirm hook."

if ! /usr/bin/grep -Fq 'shellfirm init bash' "${bash_profile}" 2>/dev/null && \
   ! bash_profile_activates_bashrc "${bash_profile}"; then
  fail "the Bash login-shell startup path was not verified."
fi

/bin/echo "VGS ShellFirm activation verified for Zsh and Bash. Open a new terminal session to load the hooks."
# Store the approved expectations only after all activation checks succeed.
# No secret is written. This descriptor supports mixed versions during rollout.
readonly state_dir='/Library/Application Support/VGS/ShellFirm/state'
for directory in '/Library/Application Support/VGS' '/Library/Application Support/VGS/ShellFirm'; do
  [[ -d "$directory" && ! -L "$directory" ]] || fail "unsafe managed directory."
  [[ "$(/usr/bin/stat -f '%u' "$directory")" == 0 ]] || fail "managed directory is not root-owned."
  mode="$(/usr/bin/stat -f '%Lp' "$directory")"
  (( (8#$mode & 0022) == 0 )) || fail "managed directory is writable by another user."
done
[[ ! -L "$state_dir" ]] || fail "state directory must not be a symlink."
/bin/mkdir -p "$state_dir"
/usr/sbin/chown root:wheel "$state_dir"
/bin/chmod 755 "$state_dir"
state_tmp="$(/usr/bin/mktemp "$state_dir/.release.XXXXXX")"
trap '/bin/rm -f "$state_tmp"' EXIT
/bin/cat > "$state_tmp" <<'VGS_APPROVED_RELEASE'
@RELEASE_PLIST@
VGS_APPROVED_RELEASE
/usr/bin/plutil -lint "$state_tmp" >/dev/null || fail "release descriptor is invalid."
/usr/sbin/chown root:wheel "$state_tmp"
/bin/chmod 644 "$state_tmp"
/bin/mv -f "$state_tmp" "$state_dir/approved-release.plist"
trap - EXIT
/bin/echo 'VGS ShellFirm release @RELEASE_ID@ activated; approved checksums recorded.'
# Log all four checks in the installation policy as well as the weekly policy.
/bin/bash -s -- "$@" <<'VGS_RELEASE_HEALTH' || fail 'post-install health verification failed.'
@HEALTHCHECK@
VGS_RELEASE_HEALTH
exit 0
