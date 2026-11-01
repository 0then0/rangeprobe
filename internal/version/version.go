// Package version holds the single source of the release version.
package version

// Version is the RangeProbe release version. Release CI verifies that it
// matches the pushed tag and the CHANGELOG.
const Version = "0.1.0"

// Repository is the project home, used in the User-Agent and reports.
const Repository = "https://github.com/0then0/rangeprobe"

// UserAgent is sent with every probe request.
func UserAgent() string {
	return "rangeprobe/" + Version + " (+" + Repository + ")"
}
