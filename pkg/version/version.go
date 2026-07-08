// Package version holds the gateway's build version. Release builds inject
// it via:
//
//	go build -ldflags "-X github.com/xnyzer/mcp-oauth-gateway/pkg/version.Version=v1.2.3"
//
// Untagged builds report "dev".
package version

// Version is the gateway build version.
var Version = "dev"
