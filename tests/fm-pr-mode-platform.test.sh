#!/usr/bin/env bash
# tests/fm-pr-mode-platform.test.sh - fm_pr_private_file_valid's mode check
# across platforms (bin/fm-pr-lib.sh: fm_pr_mode_private_ok, fm_pr_file_owner,
# _fm_pr_mode_platform).
#
# Native Windows Git Bash / MSYS derives the mode `stat` reports from NTFS
# ACLs rather than storing a POSIX mode, so a chmod'ed file does not reliably
# read back the mode it was just given. An exact-mode comparison is therefore
# unverifiable there; fm_pr_mode_private_ok substitutes a current-user-
# ownership check on that platform instead, and leaves the exact-mode
# comparison unchanged everywhere else.
#
# Unit layer only, behind deterministic fakes for fm_pr_file_mode/owner/
# device/link_count, so the branch selection itself is pinned regardless of
# which real OS runs the suite - the same reason bin/fm-session-lock-ancestry
# test.sh drives its unit cases behind a fake `ps` rather than the real
# process table. FM_PR_MODE_PLATFORM overrides detection (same shape as
# bin/fm-session-lock-lib.sh's FM_LOCK_PLATFORM) so both branches are
# exercisable from either host.
set -u

# shellcheck source=tests/lib.sh
. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

LIB="$ROOT/bin/fm-pr-lib.sh"
TMP_ROOT=$(fm_test_tmproot fm-pr-mode-platform)

FILE="$TMP_ROOT/private"
: > "$FILE"

# Run one library expression with FM_PR_MODE_PLATFORM forced, in a fresh shell
# so a fake accessor never leaks into a later assertion.
lib_eval() {  # <platform> <expression>
  local platform=$1 expr=$2
  FM_PR_MODE_PLATFORM="$platform" bash -c "
    . \"\$0\"
    $expr
  " "$LIB"
}

# --- unix: exact-mode comparison is unchanged ----------------------------

if lib_eval unix "
  fm_pr_file_mode() { printf '%s\n' 600; }
  fm_pr_file_device() { printf '%s\n' 42; }
  fm_pr_file_link_count() { printf '%s\n' 1; }
  fm_pr_private_file_valid '$FILE' 600 42
"; then
  pass "unix: a file reporting mode 600 passes the exact-mode check"
else
  fail "unix: a file reporting mode 600 should pass the exact-mode check"
fi

if lib_eval unix "
  fm_pr_file_mode() { printf '%s\n' 644; }
  fm_pr_file_device() { printf '%s\n' 42; }
  fm_pr_file_link_count() { printf '%s\n' 1; }
  fm_pr_private_file_valid '$FILE' 600 42
"; then
  fail "unix: a file reporting mode 644 must still be REJECTED against an expected mode of 600 - the strict path must not have weakened"
else
  pass "unix: a file reporting mode 644 is still rejected against an expected mode of 600 (regression guard)"
fi

# --- windows: mode bits are unverifiable, ownership substitutes ----------

if lib_eval windows "
  fm_pr_file_mode() { printf '%s\n' 644; }   # deliberately the wrong mode - windows must not care
  fm_pr_file_owner() { id -u; }
  fm_pr_file_device() { printf '%s\n' 42; }
  fm_pr_file_link_count() { printf '%s\n' 1; }
  fm_pr_private_file_valid '$FILE' 600 42
"; then
  pass "windows: a file owned by the current user passes regardless of its reported mode bits"
else
  fail "windows: a file owned by the current user should pass even though its mode bits do not read back as 600"
fi

# The ownership check is the substitute guarantee on this platform, not a
# rubber stamp: giving it a mode that WOULD satisfy the unix comparison must
# not matter, and a mismatched owner must still be refused.
if lib_eval windows "
  fm_pr_file_mode() { printf '%s\n' 600; }
  fm_pr_file_owner() { printf '%s\n' 999999999; }
  fm_pr_file_device() { printf '%s\n' 42; }
  fm_pr_file_link_count() { printf '%s\n' 1; }
  fm_pr_private_file_valid '$FILE' 600 42
"; then
  fail "windows: a file reported as owned by a different uid must be refused"
else
  pass "windows: a file reported as owned by a different uid is refused"
fi

# --- windows: the other privacy checks are still enforced, unchanged -----

if lib_eval windows "
  fm_pr_file_owner() { id -u; }
  fm_pr_file_device() { printf '%s\n' 42; }
  fm_pr_file_link_count() { printf '%s\n' 1; }
  fm_pr_private_file_valid '$FILE' 600 not-the-real-device
"; then
  fail "windows: a device mismatch must still be refused"
else
  pass "windows: a device mismatch is still refused on the windows path"
fi

if lib_eval windows "
  fm_pr_file_owner() { id -u; }
  fm_pr_file_device() { printf '%s\n' 42; }
  fm_pr_file_link_count() { printf '%s\n' 2; }
  fm_pr_private_file_valid '$FILE' 600 42
"; then
  fail "windows: a file with more than one hard link must still be refused"
else
  pass "windows: a file with more than one hard link is still refused on the windows path"
fi

echo "# fm-pr-mode-platform.test.sh: all assertions passed"
