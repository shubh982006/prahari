// Package migrations embeds both dialects' schema so the binary carries it.
// Rule M1: every migration lands in both directories in the same commit.
package migrations

import "embed"

//go:embed postgres/*.sql sqlite/*.sql
var FS embed.FS
