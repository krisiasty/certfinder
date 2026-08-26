// Package buildinfo formats version metadata injected at link time.
package buildinfo

var (
	version = "dev"
	commit  = "unknown"
	built   = "unknown"
)

// Version returns the release version this binary was built from, or "dev" for
// a build made outside the release process.
func Version() string {
	return version
}

// String returns certfinder's version, commit, and build timestamp.
func String() string {
	return "certfinder " + version + " (commit " + commit + ", built " + built + ")"
}
