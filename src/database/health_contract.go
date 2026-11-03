package database

import (
	"database/sql"
	"fmt"

	"gorm.io/gorm"
)

// ReadHealthContract batches monitoring reads without changing the contract
// reader used by startup and identity-adoption transactions.
func ReadHealthContract(db *gorm.DB) (Contract, error) {
	out := Contract{IdentityState: "unknown", LedgerState: "unknown", EnforcementMode: contractMode()}
	var ledgerExists, identityExists bool
	if err := db.Raw(`SELECT to_regclass('public.iam_schema_migrations') IS NOT NULL,
		to_regclass('public.wahb_database_identity') IS NOT NULL`).Row().Scan(&ledgerExists, &identityExists); err != nil {
		return out, err
	}
	if !ledgerExists {
		out.LedgerState = "absent"
		return out, nil
	}

	// Only fixed SQL fragments are selected, after checking table existence.
	identityFields, identityJoin := "FALSE, NULL::text, NULL::text, NULL::bigint", ""
	if identityExists {
		identityFields = "i.singleton IS NOT NULL, i.database_id::text, i.lineage_root_id::text, i.database_epoch"
		identityJoin = " LEFT JOIN public.wahb_database_identity i ON i.singleton=TRUE"
	}
	var dirty, identityPresent bool
	var databaseID, lineageRootID sql.NullString
	var epoch sql.NullInt64
	err := db.Raw(`SELECT m.version, m.dirty, `+identityFields+`
		FROM (SELECT version, dirty FROM public.iam_schema_migrations LIMIT 1) m`+identityJoin).
		Row().Scan(&out.MigrationVersion, &dirty, &identityPresent, &databaseID, &lineageRootID, &epoch)
	if err == sql.ErrNoRows {
		out.LedgerState = "absent"
		return out, nil
	}
	if err != nil {
		return out, err
	}
	if dirty {
		out.LedgerState = "dirty"
	} else if out.MigrationVersion != LatestCanonicalMigration {
		out.LedgerState = "incomplete"
	} else {
		out.LedgerState = "verified"
	}
	if identityPresent {
		if !databaseID.Valid || !lineageRootID.Valid || !epoch.Valid {
			return out, fmt.Errorf("incomplete IAM database identity")
		}
		out.DatabaseID, out.LineageRootID, out.Epoch = databaseID.String, lineageRootID.String, epoch.Int64
		out.IdentityState = "present"
	}
	return out, nil
}
