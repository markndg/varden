#!/bin/sh
# Reference deployment for Linux POSIX separation.
# This script does not run unless it is root and --apply is passed.
# Do not point it at a developer workstation. Use a disposable host or VM.
set -eu

if [ "$(id -u)" -ne 0 ] || [ "${1:-}" != "--apply" ]; then
  echo "Reference only. On a disposable Linux host, re-run as root with --apply." >&2
  echo "It creates varden-watch and varden-agent, and a root-owned authority directory the agent cannot read." >&2
  exit 2
fi

umask 077
useradd --system --create-home --home-dir /var/lib/varden-agent --shell /usr/sbin/nologin varden-agent 2>/dev/null || true
useradd --system --create-home --home-dir /var/lib/varden-watch --shell /usr/sbin/nologin varden-watch 2>/dev/null || true

install -d -o root -g varden-watch -m 0750 /var/lib/varden/protected
install -d -o varden-agent -g varden-agent -m 0750 /var/lib/varden/work
install -d -o root -g varden-watch -m 0750 /etc/varden/authority
install -d -o root -g varden-watch -m 0750 /etc/varden

# The agent is not in the varden-watch group, so mode 0640 is unreadable and unwritable by the agent.
touch /var/lib/varden/protected/monitoring.json
chown root:varden-watch /var/lib/varden/protected/monitoring.json
chmod 0640 /var/lib/varden/protected/monitoring.json
touch /etc/varden/authority/approval.key
chown root:varden-watch /etc/varden/authority/approval.key
chmod 0640 /etc/varden/authority/approval.key

echo "Users and directories created. Install the systemd units and do not add varden-agent to varden-watch."
