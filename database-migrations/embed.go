// Package migrations embeds the SQL migration files so they ship inside
// the compiled binary and can be applied from the running service via
// POST /api/v1/admin/migrations/up. The CLI workflow (`make migrate-up`)
// still works against the same files on disk.
package migrations

import "embed"

//go:embed migrations/*.sql
var Files embed.FS
