#!/usr/bin/env bash
# Shared session-lock harness identity.
#
# ONE owner of the "which verified-harness process holds this home's session
# lock, and does the current process run inside that same session?" decision.
# bin/fm-lock.sh uses it to acquire and inspect state/.lock and its
# state/.lock-session sidecar; bin/fm-claude-stop-autoarm.sh uses it to prove a
# Stop hook fires inside the lock-owning primary session before it may arm or
# rewake. Two signals decide ownership, either one sufficient: the recorded pid
# is a member of this process's contiguous harness ancestry, or the trusted
# Claude session id below matches the id recorded beside a live lock. Neither
# signal ever fails open: no id, no sidecar, an untrusted id, or a different
# recorded id leaves the ancestry verdict exactly as it was.
# This file is sourced by scripts and has no side effects on source.

# Cursor process identity is NOT expressible as a command-name pattern and is
# deliberately not added to the tables below: Cursor's installed names are
# cursor-agent and the far-too-generic legacy alias `agent`, and it runs as a
# bundled node script. bin/fm-cursor-lib.sh is the fleet's single owner of that
# decision, so this file delegates to it rather than widening the name match.
# shellcheck source=bin/fm-cursor-lib.sh
. "$(dirname -- "${BASH_SOURCE[0]}")/fm-cursor-lib.sh"

# Known harness command names; extend when a new adapter is verified. omp is
# anchored exactly like pi: its process name is the bare word `omp` (verified,
# omp 18.1.11), and a substring match would claim ompd or comp.
FM_HARNESS_RE='claude|codex|opencode|grok|kimi|^pi$|^pi-signed$|^omp$'

# The same harnesses as exact executable names. Keep in sync with
# FM_HARNESS_RE. Used only for the stricter path evidence below, where the
# loose regex would also match ordinary firstmate paths such as
# bin/fm-claude-stop-autoarm.sh.
FM_HARNESS_NAMES=(claude codex opencode grok kimi pi-signed pi omp)

# Print the exact harness name carried by executable path $1 - its own basename
# or any directory component - or return 1.
#
# This exists because Claude Code's native installer names the per-session
# executable by its version (~/.local/share/claude/versions/2.1.220), so the
# basename identifies nothing while the install path still says claude. Matching
# whole path components only is what keeps that widening safe: an ordinary path
# such as bin/fm-claude-stop-autoarm.sh or ~/.claude/hooks/notify.sh has no
# "claude" component and is correctly not a harness process.
fm_harness_path_name() {  # <path>
  local path=$1 name
  [ -n "$path" ] || return 1
  for name in "${FM_HARNESS_NAMES[@]}"; do
    case "/$path/" in
      */"$name"/*) printf '%s' "$name"; return 0 ;;
    esac
  done
  return 1
}

# True when the process described by command name $1 and full argument string $2
# is a verified harness. Sets FM_HARNESS_IS_CLAUDE for the ancestry walk.
#
# Evidence, in order:
#   1. the basename of the reported command name, against FM_HARNESS_RE.
#   2. an exact harness component in that command path or in argv[0]. Both are
#      needed because the two platforms report different things: macOS reports
#      argv[0] in `ps -o comm=`, while procps on Linux reports the kernel exec
#      name and ignores argv[0] entirely, so a version-named Claude Code binary
#      is identified by its install path on macOS and by argv[0] on Linux.
#   3. a bare interpreter (node, python) running a harness script path.
#   4. Cursor's own structural identity, owned by bin/fm-cursor-lib.sh.
FM_HARNESS_IS_CLAUDE=0
fm_harness_process_matches() {  # <comm> <args>
  local comm=$1 args=$2 base argv0 name
  FM_HARNESS_IS_CLAUDE=0
  base=$(basename -- "$comm")
  if printf '%s' "$base" | grep -qE "$FM_HARNESS_RE"; then
    case "$base" in *claude*) FM_HARNESS_IS_CLAUDE=1 ;; esac
    return 0
  fi
  argv0=${args%% *}
  if name=$(fm_harness_path_name "$comm") || name=$(fm_harness_path_name "$argv0"); then
    case "$name" in claude) FM_HARNESS_IS_CLAUDE=1 ;; esac
    return 0
  fi
  # Bare interpreter (e.g. node): match the harness name in its script path.
  case "$comm" in
    *node*|*python*)
      if printf '%s' "$args" | grep -qE "$FM_HARNESS_RE"; then
        case "$args" in *claude*) FM_HARNESS_IS_CLAUDE=1 ;; esac
        return 0
      fi
      ;;
  esac
  # Cursor: its own owner decides, from Cursor's name or versioned install tree
  # in the command path or argv[0]. Without this a Cursor primary can never
  # locate its own harness in the ancestry, so every session start refuses the
  # fleet lock as read-only and the park can never arm.
  fm_cursor_process_matches "$comm" "$args" "$argv0" && return 0
  return 1
}

# --- portable process inspection ---------------------------------------------
#
# The ancestry walk and the liveness predicate both need three facts about a
# process - its command name, full argument string, and parent pid. On Linux and
# macOS `ps -o comm=/args=/ppid= -p <pid>` supplies them. On Windows under Git
# Bash / MSYS it does NOT: the bundled ps rejects -o and only knows Cygwin/MSYS
# processes, so the Claude harness - a real ancestor two hops up the native
# Windows process tree (bash -> bash -> claude.exe) - is invisible, the ancestry
# walk finds nothing, and every session refuses the home's lock as read-only.
#
# The fix is to read the true tree from a Windows-aware source while keeping the
# harness-identity policy below unchanged. On Windows the ancestry comes from
# Win32_Process (fm-win-ancestry.ps1) and liveness from `ps -W`, which does list
# native processes with their Windows pids. Pids are reported in the platform's
# own space - Unix pids on Unix, Windows pids (WINPID) on Windows - and the lock
# stores whatever this layer reports, so every consumer compares like with like.

# Selected process-inspection platform: "windows" or "unix". FM_LOCK_PLATFORM
# overrides detection so the Windows path is exercisable from a Unix test host.
_fm_lock_platform() {
  if [ -n "${FM_LOCK_PLATFORM:-}" ]; then printf '%s\n' "$FM_LOCK_PLATFORM"; return 0; fi
  case "$(uname -s 2>/dev/null)" in
    MINGW*|MSYS*|CYGWIN*) printf 'windows\n' ;;
    *) printf 'unix\n' ;;
  esac
}

# Windows data sources, each a single seam a test can shadow (as the suite
# already shadows `kill`): this shell's MSYS pid and Windows pid, the MSYS
# logical process table, the Win32_Process ancestry walk from a start pid, and
# the native-process table.
_fm_win_self_msyspid() { printf '%s\n' "$$"; }
_fm_win_self_winpid() { cat "/proc/$$/winpid" 2>/dev/null; }
_fm_win_ps() { ps 2>/dev/null; }
_fm_win_walk_rows() {  # <start-winpid> -> pid<TAB>name<TAB>commandline, innermost first
  local start=$1 script
  script="$(dirname -- "${BASH_SOURCE[0]}")/fm-win-ancestry.ps1"
  powershell.exe -NoProfile -ExecutionPolicy Bypass -File "$script" -Start "$start" 2>/dev/null | tr -d '\r'
}
_fm_win_ps_w() { ps -W 2>/dev/null; }

# Emit the process ancestry innermost-first as: pid<TAB>comm<TAB>args, one row
# per hop, bounded to 16 hops and stopping at the first unresolvable parent.
# This is the only platform-specific step; the harness-identity policy in
# fm_harness_ancestry_pids consumes these rows without caring which host they
# came from.
_fm_ancestry_rows() {
  if [ "$(_fm_lock_platform)" = windows ]; then
    _fm_win_ancestry_rows
  else
    _fm_unix_ancestry_rows
  fi
}

_fm_unix_ancestry_rows() {
  local pid=$$ comm args
  for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16; do
    comm=$(ps -o comm= -p "$pid" 2>/dev/null) || break
    args=$(ps -o args= -p "$pid" 2>/dev/null)
    printf '%s\t%s\t%s\n' "$pid" "$comm" "$args"
    pid=$(ps -o ppid= -p "$pid" 2>/dev/null | tr -d ' ')
    { [ -n "$pid" ] && [ "$pid" -gt 1 ] 2>/dev/null; } || break
  done
}

# The walker already emits pid<TAB>name<TAB>commandline innermost-first, with the
# executable name playing the role of comm and the command line the role of args.
# It must start from a shell with a valid Windows parent link (see
# _fm_win_ancestry_start_winpid).
_fm_win_ancestry_rows() {
  local start
  start=$(_fm_win_ancestry_start_winpid)
  [ -n "$start" ] || return 0
  _fm_win_walk_rows "$start"
}

# Print the Windows pid the ancestry walk must start from. Not simply this
# shell's own winpid: an MSYS / Git Bash subprocess is fork/exec-orphaned - its
# Windows ParentProcessId points at a launcher stub that has already exited - so
# a Win32 walk from here stops at the first hop and never reaches the harness.
# The MSYS ps table still records the logical parent chain though, and the
# topmost MSYS shell in it was spawned directly by the harness (claude.exe ->
# bash), so THAT shell keeps an intact Windows parent link. Climb the MSYS chain
# to it and start the Win32 walk from its winpid. Fall back to this shell's own
# winpid when the MSYS table cannot be read.
_fm_win_ancestry_start_winpid() {
  local top
  top=$(_fm_win_top_msys_winpid)
  if [ -n "$top" ]; then printf '%s\n' "$top"; return 0; fi
  _fm_win_self_winpid | tr -d '[:space:]'
}

# Walk the MSYS logical process table from this shell to the topmost MSYS
# ancestor (the one whose parent is not itself an MSYS process) and print that
# ancestor's Windows pid. Columns are: PID PPID PGID WINPID ...
_fm_win_top_msys_winpid() {
  _fm_win_ps | awk -v self="$(_fm_win_self_msyspid)" '
    NR == 1 { next }
    { par[$1] = $2; win[$1] = $4 }
    END {
      if (!(self in win)) exit
      cur = self; top = self
      for (i = 0; i < 64 && (cur in par); i++) {
        p = par[cur]
        if (!(p in win)) break
        top = p; cur = p
      }
      print win[top]
    }
  '
}

# Look up a live Windows process by its WINPID in the native-process table.
# Prints comm<TAB>args - the executable path serving as both, which is all the
# harness matcher needs - or returns 1 when the pid is not a live native process
# with a resolvable executable path. `ps -W` columns are:
#   PID PPID PGID WINPID TTY UID STIME COMMAND...
# COMMAND is an absolute path that may contain spaces, and STIME is one token for
# recent processes (HH:MM:SS) but two for older ones (MMM DD), so the column
# offset of COMMAND is not fixed. Anchor on the first drive-letter path, UNC
# path, or MSYS-mangled POSIX path (`/c/...`, which `ps -W` reports for at
# least some native processes instead of their Windows-style path) token
# instead and rejoin to end of line. A native process whose COMMAND is a bare
# name (System, Registry) has no such token and is never a harness, so it is
# correctly reported as not found.
_fm_win_proc_info() {  # <winpid>
  _fm_win_ps_w | awk -v w="$1" '
    $4 == w {
      start = 0
      for (i = 5; i <= NF; i++) {
        if ($i ~ /^[A-Za-z]:[\\\/]/ || $i ~ /^\\\\/ || $i ~ /^\/[A-Za-z]\//) { start = i; break }
      }
      if (start == 0) next
      cmd = ""
      for (i = start; i <= NF; i++) cmd = cmd (i > start ? " " : "") $i
      printf "%s\t%s\n", cmd, cmd
      found = 1
      exit
    }
    END { if (!found) exit 1 }
  '
}

# Walk the current process ancestry (up to 16 hops) and print this session's
# contiguous verified-harness ancestry, innermost pid first.
#
# The walk climbs freely until the first harness match, because the caller is
# normally an ordinary shell several levels below its session. After that first
# match it stops at the first non-harness ancestor, so it can never cross a gap
# into an unrelated harness further up the real process tree - for example the
# live session that launched a test as its own subprocess.
#
# For every harness except Claude the innermost match is the session, which is
# where e.g. Pi's shared signed-wrapper ancestry actually holds the lock: a
# "pi-signed" launcher can be the direct parent of the inner "pi" engine pid that
# owns the lock, and the wrapper pid above it is not that owner. Claude Code
# instead runs hooks several levels below the session inside its own nested
# worker chain (hook shell -> claude bg-spare -> claude bg-pty-host -> claude ->
# claude), with no non-harness process between them. Which pid in that run is the
# session cannot be read off the ancestry at all, so the whole contiguous run is
# reported and the callers below decide what they need from it.
fm_harness_ancestry_pids() {
  local pid comm args extending=0 printed=0
  while IFS=$'\t' read -r pid comm args; do
    [ -n "$pid" ] || continue
    if fm_harness_process_matches "$comm" "$args"; then
      printf '%s\n' "$pid"
      printed=1
      [ "$FM_HARNESS_IS_CLAUDE" -eq 1 ] || break
      extending=1
    elif [ "$extending" -eq 1 ]; then
      break
    fi
  done <<EOF
$(_fm_ancestry_rows)
EOF
  [ "$printed" -eq 1 ]
}

# Print the outermost pid of this session's contiguous harness run for callers
# that need that ancestry identity. This is not necessarily the pid written to
# the session lock: fm_session_lock_anchor_pid owns that choice and uses a
# trusted Claude session's model-loop pid instead. Every non-Claude harness
# reports a single pid, so this remains its innermost match unchanged.
fm_harness_ancestry_pid() {
  local pids
  pids=$(fm_harness_ancestry_pids) || return 1
  _fm_harness_outermost_pid "$pids"
}

# Print the last (outermost) pid of ancestry list $1, or return 1 when empty.
_fm_harness_outermost_pid() {  # <ancestry-pids>
  local pid outermost=''
  while IFS= read -r pid; do
    [ -n "$pid" ] && outermost=$pid
  done <<EOF
$1
EOF
  [ -n "$outermost" ] || return 1
  printf '%s\n' "$outermost"
}

# True if $1 is a live process that looks like a verified harness. On Windows the
# pid is a WINPID: `kill -0` would test the wrong (MSYS) pid space, so existence
# and identity are read together from the native-process table instead.
fm_harness_pid_alive() {
  local pid=$1 comm args info
  if [ "$(_fm_lock_platform)" = windows ]; then
    info=$(_fm_win_proc_info "$pid") || return 1
    [ -n "$info" ] || return 1
    comm=${info%%$'\t'*}
    args=${info#*$'\t'}
    fm_harness_process_matches "$comm" "$args"
    return
  fi
  kill -0 "$pid" 2>/dev/null || return 1
  comm=$(ps -o comm= -p "$pid" 2>/dev/null) || return 1
  args=$(ps -o args= -p "$pid" 2>/dev/null)
  fm_harness_process_matches "$comm" "$args"
}

# --- trusted same-session identity -------------------------------------------
# Claude Code hands every hook and tool shell CLAUDE_CODE_SESSION_ID (the
# session's conversation id) and CLAUDE_PID (the pid of the process running the
# model loop). A background session runs that model loop in a transient helper
# bridged to its front-end by a shared daemon, and when that bridge is recycled
# the contiguous claude-named ancestry from a hook to the recorded lock owner
# breaks while the owner pid stays alive, so ancestry alone reads the session's
# own lock as another live session's. The id is the one identity that survives
# the recycling, so it is accepted as a second ownership signal - but only from
# an environment proven to belong to the current Claude run.
#
# Trust gate: CLAUDE_PID must be a Claude-shaped member of this process's
# contiguous harness ancestry. An id merely retained in a helper environment
# fails that membership and is ignored: a hand-started Pi or codex primary under
# a Claude pane still carries the pane's CLAUDE_CODE_SESSION_ID and CLAUDE_PID,
# and must never own a lock with them. Ids are read from the environment only,
# never from ps argv, where prompts and briefs are visible.
#
# A --fork-session successor mints a new id, so it stays a foreign live owner
# until the pre-fork process exits; that is the safe direction and a documented
# non-goal. Two genuinely different live sessions sharing one id is not a
# supported state (Claude refuses to resume a running session under its id).

# Print the Claude session id this process may own with, or return 1. $1 is the
# ancestry list an earlier walk already produced, so a caller that walked once
# need not walk again.
fm_session_lock_trusted_session_id() {  # [<ancestry-pids>]
  local id=${CLAUDE_CODE_SESSION_ID:-} claude_pid=${CLAUDE_PID:-} pids=${1:-} pid comm args
  [ -n "$id" ] || return 1
  case "$id" in *$'\n'*|*$'\r'*) return 1 ;; esac
  case "$claude_pid" in ''|*[!0-9]*) return 1 ;; esac
  if [ -z "$pids" ]; then
    pids=$(fm_harness_ancestry_pids) || return 1
  fi
  while IFS= read -r pid; do
    [ "$pid" = "$claude_pid" ] || continue
    comm=$(ps -o comm= -p "$pid" 2>/dev/null) || return 1
    args=$(ps -o args= -p "$pid" 2>/dev/null)
    fm_harness_process_matches "$comm" "$args" || return 1
    [ "$FM_HARNESS_IS_CLAUDE" -eq 1 ] || return 1
    printf '%s\n' "$id"
    return 0
  done <<EOF
$pids
EOF
  return 1
}

# Print the session id recorded beside the lock in state dir $1, or return 1.
# bin/fm-lock.sh is the only writer of state/.lock-session; a missing,
# symlinked, unreadable, or empty sidecar, or one whose first line contains a
# newline or carriage return, is simply no recorded id.
fm_session_lock_recorded_session_id() {  # <state>
  local state=$1 recorded
  [ -f "$state/.lock-session" ] && [ ! -L "$state/.lock-session" ] || return 1
  recorded=$(head -n 1 "$state/.lock-session" 2>/dev/null) || return 1
  [ -n "$recorded" ] || return 1
  case "$recorded" in *$'\n'*|*$'\r'*) return 1 ;; esac
  printf '%s\n' "$recorded"
}

# True when the lock in state dir $1 was recorded by this same Claude session:
# the trusted id equals the id recorded beside the lock. No trusted id, no
# sidecar, or a different recorded id is false.
fm_session_lock_same_session() {  # <state> [<ancestry-pids>]
  local state=$1 trusted recorded
  trusted=$(fm_session_lock_trusted_session_id "${2:-}") || return 1
  recorded=$(fm_session_lock_recorded_session_id "$state") || return 1
  [ "$recorded" = "$trusted" ]
}

# Print the pid bin/fm-lock.sh records on lock line 1 for this session. For a
# Claude session with a trusted id that is CLAUDE_PID, the model-loop process:
# never the shared transient daemon and never a front-end that outlives the
# session, so "recorded pid dead" keeps meaning "session gone" instead of
# wedging a home behind a live daemon whose session died. A replaced background
# helper leaves a dead pid that its own session's next hook reclaims, because
# the sidecar still names that session. Every other session records the
# outermost pid of its contiguous run, exactly as before.
fm_session_lock_anchor_pid() {
  local pids
  pids=$(fm_harness_ancestry_pids) || return 1
  if fm_session_lock_trusted_session_id "$pids" >/dev/null; then
    printf '%s\n' "$CLAUDE_PID"
    return 0
  fi
  _fm_harness_outermost_pid "$pids"
}

# True when state dir $1 holds a session lock that this process's session owns:
# the recorded pid is ANY harness ancestor of the current process, or the lock
# was recorded by this same trusted Claude session and its recorded pid is still
# a live harness. Membership is the honest ancestry test, because the lock owner
# sits at an unknown depth in a contiguous Claude run - it is the outermost pid
# when the hook fires inside the session's own nested worker chain, and an inner
# pid when a harness-named daemon parents the session. The same-session path
# requires the recorded pid alive so that a dead one is reclaimed through
# bin/fm-lock.sh's ordinary stale-owner path, which refreshes line 1, rather than
# silently owned with a dead anchor. A missing lock, a malformed lock, a lock
# held by a harness outside this ancestry under another (or no) session id, or
# an ancestry that cannot be resolved all fail closed.
fm_session_lock_owned_by_self() {
  local state=$1 lock_pid pids pid
  lock_pid=$(cat "$state/.lock" 2>/dev/null || true)
  case "$lock_pid" in
    ''|*[!0-9]*) return 1 ;;
  esac
  pids=$(fm_harness_ancestry_pids) || return 1
  while IFS= read -r pid; do
    [ "$pid" = "$lock_pid" ] && return 0
  done <<EOF
$pids
EOF
  fm_session_lock_same_session "$state" "$pids" || return 1
  fm_harness_pid_alive "$lock_pid"
}

# True when state dir $1 records a live verified harness outside this process's
# contiguous harness ancestry that was not recorded by this same trusted Claude
# session. Sets FM_SESSION_LOCK_FOREIGN_OWNER_PID for a diagnostic caller.
# Malformed, missing, dead, and ancestry-uncertain locks are not foreign-owner
# evidence.
# shellcheck disable=SC2034 # Output global, read by the sourcing guard caller.
FM_SESSION_LOCK_FOREIGN_OWNER_PID=
fm_session_lock_foreign_owner_live() {
  local state=$1 lock_pid pids pid
  FM_SESSION_LOCK_FOREIGN_OWNER_PID=
  [ -f "$state/.lock" ] && [ ! -L "$state/.lock" ] || return 1
  lock_pid=$(cat "$state/.lock" 2>/dev/null || true)
  case "$lock_pid" in
    ''|*[!0-9]*) return 1 ;;
  esac
  fm_harness_pid_alive "$lock_pid" || return 1
  pids=$(fm_harness_ancestry_pids) || return 1
  while IFS= read -r pid; do
    [ "$pid" = "$lock_pid" ] && return 1
  done <<EOF
$pids
EOF
  fm_session_lock_same_session "$state" "$pids" && return 1
  # shellcheck disable=SC2034 # Output global, read by the sourcing guard caller.
  FM_SESSION_LOCK_FOREIGN_OWNER_PID=$lock_pid
  return 0
}
