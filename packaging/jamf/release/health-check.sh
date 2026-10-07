#!/bin/bash
# VGS CI health check: verify the installed approved release and saved user hooks.
# Read-only. Does not install, repair, run ShellFirm, source profiles, or save state.
# Hook presence is a configuration check, not proof about already-open terminals.
set -u
set -o pipefail
export PATH=/usr/bin:/bin:/usr/sbin:/sbin
export LC_ALL=C

readonly REVISION='2026.10.06-release-aware-1'
readonly BINARY='/Library/Application Support/VGS/ShellFirm/bin/shellfirm'
readonly COMMAND='/usr/local/bin/shellfirm'
readonly POLICY='/Library/Application Support/VGS/ShellFirm/policy/.shellfirm.yaml'
POLICY_SHA256='3d48741d6a357ce849f5fe5abe617fadc6e52bf44116fd3b5d155a74aeca1ed4'
readonly RUN_UID="$(/usr/bin/id -u)"
readonly JAMF_USER="${3:-}"
BINARY_VERSION='0.3.10.2'
POLICY_VERSION='2026.08.1.1'
BINARY_SHA256=''
release_error=''
readonly RELEASE_STATE='/Library/Application Support/VGS/ShellFirm/state/approved-release.plist'

# Receipts alone are not proof of intact content. CI releases supply the expected
# payload hashes in a root-owned descriptor written only after activation passes.
# Macs awaiting their first CI release retain the reviewed baseline expectations.
load_release() {
    local directory owner mode value
    [ ! -e "$RELEASE_STATE" ] && [ ! -L "$RELEASE_STATE" ] && return 0
    for directory in '/Library/Application Support/VGS' '/Library/Application Support/VGS/ShellFirm' '/Library/Application Support/VGS/ShellFirm/state'; do
        [ -d "$directory" ] && [ ! -L "$directory" ] || return 1
        owner=$(/usr/bin/stat -f '%u' "$directory") || return 1
        mode=$(/usr/bin/stat -f '%Lp' "$directory") || return 1
        [ "$owner" = 0 ] && [ $((8#$mode & 0022)) -eq 0 ] || return 1
    done
    [ -f "$RELEASE_STATE" ] && [ ! -L "$RELEASE_STATE" ] || return 1
    [ "$(/usr/bin/stat -f '%u:%Lp' "$RELEASE_STATE")" = '0:644' ] || return 1
    [ "$(/usr/bin/plutil -extract schema raw -o - "$RELEASE_STATE")" = 1 ] || return 1
    BINARY_VERSION=$(/usr/bin/plutil -extract binary_version raw -o - "$RELEASE_STATE") || return 1
    POLICY_VERSION=$(/usr/bin/plutil -extract policy_version raw -o - "$RELEASE_STATE") || return 1
    BINARY_SHA256=$(/usr/bin/plutil -extract binary_sha256 raw -o - "$RELEASE_STATE") || return 1
    POLICY_SHA256=$(/usr/bin/plutil -extract policy_sha256 raw -o - "$RELEASE_STATE") || return 1
    for value in "$BINARY_VERSION" "$POLICY_VERSION"; do
        [[ "$value" =~ ^[0-9]+(\.[0-9]+){2,3}$ ]] || return 1
    done
    for value in "$BINARY_SHA256" "$POLICY_SHA256"; do
        [[ "$value" =~ ^[0-9a-f]{64}$ ]] || return 1
    done
}
if ! load_release 2>/dev/null; then
    release_error='approved release descriptor is invalid, unreadable, or not securely owned'
fi
passed=0 failed=0 not_checked=0
reason='' target_user='' target_uid='' target_home=''

problem() { reason="$1"; return 1; }

normalize_version() {
    /usr/bin/awk '/^[0-9]+(\.[0-9]+)*$/ {
        n=split($0,a,"."); for(i=1;i<=n;i++) printf "%s%d",(i>1?".":""),a[i]+0;
        print ""; valid=1 } END { if(!valid) exit 1 }' <<< "$1"
}

receipt_matches() {
    local record actual expected
    record=$(/usr/sbin/pkgutil --pkg-info "$1" 2>/dev/null) || {
        problem "package receipt missing or unreadable: $1"; return 1;
    }
    actual=$(/usr/bin/awk '$1=="version:" {print $2}' <<< "$record")
    actual=$(normalize_version "$actual") || { problem "unreadable receipt version: $1"; return 1; }
    expected=$(normalize_version "$2") || return 1
    [ "$actual" = "$expected" ] || { problem "expected package version $2; found $actual"; return 1; }
}

check_binary() {
    [ -z "$release_error" ] || { problem "$release_error"; return 1; }
    receipt_matches 'io.vgs.shellfirm.binary' "$BINARY_VERSION" || return 1
    [ "$(/usr/sbin/sysctl -n hw.optional.arm64 2>/dev/null)" = 1 ] || { problem 'Apple Silicon hardware not detected'; return 1; }
    [ -f "$BINARY" ] && [ -s "$BINARY" ] && [ -x "$BINARY" ] || { problem 'managed binary missing, empty, or not executable'; return 1; }
    [ -L "$COMMAND" ] && [ "$(/usr/bin/readlink "$COMMAND")" = "$BINARY" ] || { problem 'managed command link missing or incorrect'; return 1; }
    if [ -n "$BINARY_SHA256" ]; then
        [ "$(/usr/bin/shasum -a 256 "$BINARY" | /usr/bin/awk '{print $1}')" = "$BINARY_SHA256" ] || {
            problem 'managed binary checksum does not match the activated release'; return 1;
        }
    fi
    reason="package receipt $BINARY_VERSION, executable payload, and command link verified"
}

check_policy() {
    local digest
    [ -z "$release_error" ] || { problem "$release_error"; return 1; }
    receipt_matches 'io.vgs.shellfirm.policy' "$POLICY_VERSION" || return 1
    [ -f "$POLICY" ] && [ ! -L "$POLICY" ] || { problem 'managed policy file missing'; return 1; }
    digest=$(/usr/bin/shasum -a 256 "$POLICY" 2>/dev/null | /usr/bin/awk '{print $1}') || {
        problem 'managed policy file could not be read'; return 1;
    }
    [ "$digest" = "$POLICY_SHA256" ] || { problem "managed policy does not match activated release $POLICY_VERSION"; return 1; }
    reason='package receipt and matching policy file present'
}

supported_user() {
    local uid
    case "${1:-}" in ''|root|loginwindow|_mbsetupuser|*[!A-Za-z0-9._-]*) return 1 ;; esac
    uid=$(/usr/bin/id -u "$1" 2>/dev/null) || return 1
    [ "$uid" -ge 501 ]
}

# Match script 94: console user first, Jamf parameter 3 only as a fallback.
select_user() {
    target_user=$(/usr/bin/stat -f '%Su' /dev/console 2>/dev/null) || target_user=''
    if ! supported_user "$target_user"; then target_user="$JAMF_USER"; fi
    if ! supported_user "$target_user"; then reason='no logged-in user or eligible Jamf user'; return 2; fi
    target_uid=$(/usr/bin/id -u "$target_user") || return 1
    target_home=$(/usr/bin/dscl . -read "/Users/$target_user" NFSHomeDirectory 2>/dev/null) || {
        problem "cannot read home directory for $target_user"; return 1;
    }
    target_home="${target_home#NFSHomeDirectory: }"
    case "$target_home" in /Users/*) ;; *) problem "unsupported home directory for $target_user"; return 1 ;; esac
    [ -d "$target_home" ] || { problem "home directory unavailable for $target_user"; return 1; }
}

# Use only fixed system readers as the selected user. Never execute their profiles.
as_user() {
    if [ "$RUN_UID" = "$target_uid" ]; then "$@"
    else /usr/bin/sudo -n -u "$target_user" -- "$@"; fi
}

startup_configured() {
    local file="$1" shell="$2"
    as_user /bin/test -f "$file" && as_user /bin/test -r "$file" || return 1
    as_user /usr/bin/awk -v shell="$shell" '
        /^[[:space:]]*#/ {next}
        {
            line=$0; sub(/^[[:space:]]+/,"",line); sub(/[[:space:]]+#.*/,"",line);
            sub(/[[:space:]]+$/,"",line); sub(/;$/,"",line);
            hook="eval \"$(shellfirm init " (shell=="login"?"bash":shell) ")\"";
            if(line==hook) found=1;
            # Same Bash startup-source recognition used by activation script 94.
            if(shell=="login" && line ~ /(^|[[:space:];&|])(source|\.)[[:space:]]+.*\.bashrc/) found=1;
        }
        END {exit(found?0:1)}' "$file" 2>/dev/null
}

check_hooks() {
    select_user || return $?
    [ -L "$target_home/.shellfirm.yaml" ] &&
        [ "$(/usr/bin/readlink "$target_home/.shellfirm.yaml")" = "$POLICY" ] || {
            problem "user=$target_user: managed policy link missing or incorrect"; return 1;
        }
    as_user /bin/test -r "$POLICY" && as_user /bin/test -x "$COMMAND" || {
        problem "user=$target_user: managed policy or binary inaccessible"; return 1;
    }
    startup_configured "$target_home/.zshrc" zsh || { problem "user=$target_user: Zsh hook missing or unreadable"; return 1; }
    startup_configured "$target_home/.bashrc" bash || { problem "user=$target_user: Bash hook missing or unreadable"; return 1; }
    startup_configured "$target_home/.bash_profile" login || { problem "user=$target_user: Bash login hook missing or unreadable"; return 1; }
    reason="user=$target_user: managed policy link and Zsh/Bash startup configuration present"
}

report_check() {
    local key="$1" label="$2" function="$3" result status
    reason=''
    if "$function"; then status='PASS'; passed=$((passed+1))
    else
        result=$?
        if [ "$result" -eq 2 ]; then status='NOT_CHECKED'; not_checked=$((not_checked+1))
        else status='FAIL'; failed=$((failed+1)); fi
    fi
    /usr/bin/printf '%s=%s | %s | %s\n' "$key" "$status" "$label" "$reason"
}

/bin/echo "VGS ShellFirm weekly health check | revision=$REVISION"
report_check CHECK_1_BINARY "VGS ShellFirm Binary $BINARY_VERSION (Apple Silicon)" check_binary
report_check CHECK_2_POLICY "VGS ShellFirm Policy $POLICY_VERSION" check_policy
report_check CHECK_3_USER_HOOKS 'VGS ShellFirm - User Hooks' check_hooks
if [ "$failed" -gt 0 ]; then
    /bin/echo "RESULT=FAIL | passed=$passed failed=$failed not_checked=$not_checked"; exit 1
elif [ "$not_checked" -gt 0 ]; then
    /bin/echo "RESULT=INCOMPLETE | passed=$passed failed=0 not_checked=$not_checked"; exit 2
fi
/bin/echo 'RESULT=PASS | 3/3 checks passed'
exit 0
