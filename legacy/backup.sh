#!/usr/bin/env bash
# hessenbox encrypted mail archive — backup
# fetch both mailboxes via mbsync, then restic into ~/Nextcloud/email-archive
# (the Nextcloud desktop client syncs the repo to next.hessenbox automatically)
set -euo pipefail

export RESTIC_REPOSITORY="$HOME/Nextcloud/email-archive"
export RESTIC_PASSWORD_FILE="$HOME/.config/restic/email-archive.pass"

# 1. fetch
mbsync -a

# 2. snapshot (dedup: only new/changed messages cost storage)
restic backup \
  "$HOME/mail-archive/faculty" \
  "$HOME/mail-archive/verwaltung" \
  --tag mails --host heim \
  --verbose

# 3. retention (cheap; prune is separate so it doesn't repack the synced repo every run)
restic forget --keep-daily 7 --keep-weekly 8 --keep-monthly 24 --keep-yearly 3
