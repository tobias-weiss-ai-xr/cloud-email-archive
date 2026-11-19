#!/usr/bin/env bash
# one-time setup: passwords, keys, repo init
set -euo pipefail

mkdir -p ~/.config/imap-passwords ~/.config/restic
chmod 700 ~/.config/imap-passwords

for acct in faculty verwaltung; do
  if [ ! -f ~/.config/imap-passwords/$acct ]; then
    read -rsp "IMAP password for $acct: " pw; echo
    printf '%s\n' "$pw" > ~/.config/imap-passwords/$acct
    chmod 600 ~/.config/imap-passwords/$acct
  fi
done

if [ ! -f ~/.config/restic/email-archive.pass ]; then
  read -rsp "New restic repo password (BACK IT UP — archive unreadable without it): " pw; echo
  printf '%s\n' "$pw" > ~/.config/restic/email-archive.pass
  chmod 600 ~/.config/restic/email-archive.pass
fi

cp mbsyncrc ~/.mbsyncrc
chmod 600 ~/.mbsyncrc

export RESTIC_REPOSITORY="$HOME/Nextcloud/email-archive"
export RESTIC_PASSWORD_FILE="$HOME/.config/restic/email-archive.pass"
restic init
echo "done — run ./backup.sh and verify with 'restic snapshots'"
