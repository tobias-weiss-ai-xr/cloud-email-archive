#!/usr/bin/env bash
# hessenbox encrypted mail archive — compaction
# Run monthly (manually or cron). Repacks the restic repo in-place in the synced
# folder. Keep the Nextcloud client idle on THIS machine while it runs.
set -euo pipefail

export RESTIC_REPOSITORY="$HOME/Nextcloud/email-archive"
export RESTIC_PASSWORD_FILE="$HOME/.config/restic/email-archive.pass"

restic check
restic prune
