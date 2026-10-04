#!/usr/bin/env bash
# Edit the live config without being able to take the site down with a typo.
#
#   sudo bash edit-config.sh
#
# It opens a COPY of /etc/uninvited/config.yaml in your editor. When you save and quit it
# checks the copy (python -m uninvited --check). If the check fails it shows the problem
# and lets you fix it or throw the edit away; the live file is not touched. If the
# check passes it keeps a backup, installs the copy, restarts the service and waits
# for the dashboard. If the service does not come back it puts the backup back and
# restarts again.
#
# Everything the script runs can be redirected with an environment variable, which is
# how it is tested without a server: UNINVITED_CONF, UNINVITED_HOME, UNINVITED_PY, UNINVITED_RUNAS,
# UNINVITED_RESTART, UNINVITED_HEALTH.
set -uo pipefail

CONF=${UNINVITED_CONF:-/etc/uninvited/config.yaml}
HOME_DIR=${UNINVITED_HOME:-/opt/uninvited}
PY=${UNINVITED_PY:-$HOME_DIR/.venv/bin/python}
RUNAS=${UNINVITED_RUNAS-runuser -u uninvited --}
RESTART=${UNINVITED_RESTART:-systemctl restart uninvited}
HEALTH=${UNINVITED_HEALTH:-curl -fsS -o /dev/null http://127.0.0.1:8090/api/split}
EDIT=${EDITOR:-nano}

[ -n "${UNINVITED_RUNAS+x}" ] || [ "$(id -u)" -eq 0 ] || { echo "run with sudo"; exit 1; }
[ -f "$CONF" ] || { echo "no config at $CONF"; exit 1; }

work=$(mktemp /tmp/uninvited-config.XXXXXX)
trap 'rm -f "$work"' EXIT
cp "$CONF" "$work"
# The service user has to be able to read the copy to check it.
if [ -z "${UNINVITED_RUNAS+x}" ]; then chgrp uninvited "$work" 2>/dev/null || true; fi
chmod 640 "$work"

check() { (cd "$HOME_DIR" && $RUNAS "$PY" -m uninvited --check -c "$work"); }

while true; do
  $EDIT "$work"
  if cmp -s "$CONF" "$work"; then
    echo "No changes, nothing to do."
    exit 0
  fi
  if check; then
    break
  fi
  echo
  printf 'The edit has a problem (above). [e]dit again, or [d]iscard it and leave the live file alone? '
  read -r answer || answer=d
  case "$answer" in
    e|E|edit) ;;
    *) echo "Discarded. $CONF was not changed."; exit 1 ;;
  esac
done

backup="$CONF.bak.$(date +%Y%m%d-%H%M%S)"
cp -p "$CONF" "$backup"
cp "$work" "$CONF"
echo "Installed. Backup of the old file: $backup"

echo "Restarting..."
$RESTART
healthy=0
for _ in $(seq 1 30); do
  sleep 1
  if $HEALTH 2>/dev/null; then healthy=1; break; fi
done

if [ "$healthy" -eq 1 ]; then
  echo "OK. The service is back and the dashboard answers."
  exit 0
fi

echo "The service did not come back with the new file. Putting the old one back."
cp -p "$backup" "$CONF"
$RESTART
sleep 3
if $HEALTH 2>/dev/null; then
  echo "Restored. The site is running on the old config. Your edit is kept at $work.rejected"
  cp "$work" "$work.rejected"
  exit 1
fi
echo "Still not healthy after the restore. Look at: journalctl -u uninvited -n 40 --no-pager"
exit 2
