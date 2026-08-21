package database

import (
	"database/sql"
	"fmt"
	"os"
	"strconv"
	"strings"

	"gorm.io/gorm"
)

const LatestCanonicalMigration int64 = 19

type Contract struct {
	DatabaseID       string `json:"database_id"`
	LineageRootID    string `json:"lineage_root_id"`
	Epoch            int64  `json:"epoch"`
	IdentityState    string `json:"identity_state"`
	LedgerState      string `json:"ledger_state"`
	MigrationVersion int64  `json:"migration_version"`
	EnforcementMode  string `json:"enforcement_mode"`
}

func ReadContract(db *gorm.DB) (Contract, error) {
	out := Contract{IdentityState: "unknown", LedgerState: "unknown", EnforcementMode: contractMode()}
	var ledgerExists bool
	if err := db.Raw(`SELECT to_regclass('public.iam_schema_migrations') IS NOT NULL`).Scan(&ledgerExists).Error; err != nil {
		return out, err
	}
	if !ledgerExists {
		out.LedgerState = "absent"
		return out, nil
	}
	var dirty bool
	if err := db.Raw(`SELECT version,dirty FROM iam_schema_migrations LIMIT 1`).Row().Scan(&out.MigrationVersion, &dirty); err != nil {
		if err == sql.ErrNoRows {
			out.LedgerState = "absent"
			return out, nil
		}
		return out, err
	}
	if dirty {
		out.LedgerState = "dirty"
	} else if out.MigrationVersion != LatestCanonicalMigration {
		out.LedgerState = "incomplete"
	} else {
		out.LedgerState = "verified"
	}
	var identityExists bool
	if err := db.Raw(`SELECT to_regclass('public.wahb_database_identity') IS NOT NULL`).Scan(&identityExists).Error; err != nil {
		return out, err
	}
	if !identityExists {
		return out, nil
	}
	if err := db.Raw(`SELECT database_id::text,lineage_root_id::text,database_epoch FROM wahb_database_identity WHERE singleton=TRUE`).Row().Scan(&out.DatabaseID, &out.LineageRootID, &out.Epoch); err != nil {
		if err == sql.ErrNoRows {
			return out, nil
		}
		return out, err
	}
	out.IdentityState = "present"
	return out, nil
}
func contractMode() string {
	if strings.EqualFold(strings.TrimSpace(os.Getenv("IAM_DATABASE_CONTRACT_MODE")), "enforce") {
		return "enforce"
	}
	return "observe"
}
func EnforceContract(contract Contract) error {
	if contract.EnforcementMode != "enforce" {
		return nil
	}
	if contract.LedgerState != "verified" || contract.IdentityState != "present" {
		return fmt.Errorf("IAM database contract is not verified")
	}
	expectedID := strings.TrimSpace(os.Getenv("IAM_EXPECTED_DATABASE_ID"))
	if expectedID == "" || expectedID != contract.DatabaseID {
		return fmt.Errorf("IAM database identity does not match configured target")
	}
	rawEpoch := strings.TrimSpace(os.Getenv("IAM_EXPECTED_DATABASE_EPOCH"))
	epoch, err := strconv.ParseInt(rawEpoch, 10, 64)
	if err != nil || epoch != contract.Epoch {
		return fmt.Errorf("IAM database epoch does not match configured target")
	}
	return nil
}
