#!/bin/sh
# Install the privacyfilter substitution-log logrotate rule.
# Checks that logrotate runs on this host, then installs the rule with the
# log path and file mode the plugin will write.
set -eu

ROOT=$(CDPATH='' cd -- "$(dirname "$0")/.." && pwd)
SOURCE=${SOURCE:-"$ROOT/deploy/logrotate/privacyfilter-substitutions"}
DEST=${DEST:-/etc/logrotate.d/privacyfilter-substitutions}
LOG_PATH=${LOG_PATH:-/opt/cli-proxy-api/logs/privacyfilter-substitutions.jsonl}
LOG_DIR=$(dirname "$LOG_PATH")
LOG_MODE=${LOG_MODE:-0640}
DIR_MODE=${DIR_MODE:-0750}

die() {
  printf 'install-substitution-logrotate: %s\n' "$1" >&2
  exit 1
}

need() {
  command -v "$1" >/dev/null 2>&1 || die "required command not found: $1"
}

need install
need logrotate
need sed
need mktemp

[ -f "$SOURCE" ] || die "missing logrotate source: $SOURCE"
[ -d /etc/logrotate.d ] || die "/etc/logrotate.d does not exist"

# systemd timer is enough. A masked timer is acceptable when daily cron runs
# logrotate instead, which is how some hosts avoid a double schedule.
timer_ok=0
if [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1; then
  if systemctl is-enabled logrotate.timer >/dev/null 2>&1; then
    timer_ok=1
  fi
fi
cron_ok=0
if [ -f /etc/cron.daily/logrotate ] || [ -f /etc/periodic/daily/logrotate ]; then
  cron_ok=1
fi
if [ "$timer_ok" -ne 1 ] && [ "$cron_ok" -ne 1 ]; then
  die "logrotate is not scheduled (no enabled logrotate.timer and no daily cron)"
fi

if [ -d "$LOG_DIR" ]; then
  dir_mode=$(stat -c '%a' "$LOG_DIR")
  case "$dir_mode" in
    755 | 750 | 700) ;;
    *) die "log directory mode is $dir_mode, want 755, 750, or 700: $LOG_DIR" ;;
  esac
else
  install -d -m "$DIR_MODE" "$LOG_DIR"
fi
# A root-owned log is required so logrotate can rename it. Group/other write
# is rejected because the file contains matched plaintext.
if [ -e "$LOG_PATH" ]; then
  [ -f "$LOG_PATH" ] || die "log path exists and is not a regular file: $LOG_PATH"
  chmod "$LOG_MODE" "$LOG_PATH"
  chown root:root "$LOG_PATH"
else
  install -m "$LOG_MODE" -o root -g root /dev/null "$LOG_PATH"
fi

owner=$(stat -c '%U:%G' "$LOG_PATH")
mode=$(stat -c '%a' "$LOG_PATH")
[ "$owner" = "root:root" ] || die "log owner is $owner, want root:root"
[ "$mode" = "640" ] || die "log mode is $mode, want 640"

tmp=$(mktemp)
sed "s|^/opt/cli-proxy-api/logs/privacyfilter-substitutions.jsonl|$LOG_PATH|" "$SOURCE" >"$tmp"
install -m 0644 -o root -g root "$tmp" "$DEST"
rm -f "$tmp"

logrotate -d "$DEST" >/tmp/privacyfilter-logrotate-debug.txt 2>&1 || {
  cat /tmp/privacyfilter-logrotate-debug.txt >&2
  die "logrotate -d failed for $DEST"
}
grep -q "$LOG_PATH" /tmp/privacyfilter-logrotate-debug.txt || die "logrotate debug did not mention $LOG_PATH"
rm -f /tmp/privacyfilter-logrotate-debug.txt

printf 'installed %s\n' "$DEST"
printf 'log %s mode %s owner %s\n' "$LOG_PATH" "$mode" "$owner"
