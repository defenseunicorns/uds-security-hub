package cmd

import (
	"fmt"
	"runtime/debug"
)

// Version can be set via:
// -ldflags="-X 'github.com/defenseunicorns/uds-security-hub/cmd.Version=$TAG'"
var Version string

// CommitSHA can be set via:
// -ldflags="-X 'github.com/defenseunicorns/uds-security-hub/cmd.CommitSHA=$SHA'"
var CommitSHA string = "HEAD"

func init() {
	if Version == "" {
		i, ok := debug.ReadBuildInfo()
		if !ok {
			return
		}
		Version = i.Main.Version
	}
}

func VersionJSON() string {
	return fmt.Sprintf(`{"version": "%s", "commit": "%s"}`, Version, CommitSHA)
}
