// Command cea is the cloud-email-archive binary: an encrypted, append-only
// email archive synced to any cloud folder. All logic lives in
// internal/app; this file only wires os.Exit to the run loop.
package main

import (
	"os"

	"github.com/tobias-weiss-ai-xr/cloud-email-archive/internal/app"
)

func main() {
	os.Exit(app.Run(os.Args[1:]))
}
