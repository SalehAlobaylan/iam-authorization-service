package database

import (
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func TestReadHealthContractCompatibility(t *testing.T) {
	t.Setenv("IAM_DATABASE_CONTRACT_MODE", "observe")
	for _, tc := range []struct {
		name, ledgerState, identityState                string
		ledger, identity, ledgerRow, identityRow, dirty bool
		version                                         int64
	}{
		{name: "missing ledger", ledgerState: "absent", identityState: "unknown"},
		{name: "empty ledger", ledger: true, identity: true, ledgerState: "absent", identityState: "unknown"},
		{name: "missing identity table", ledger: true, ledgerRow: true, version: LatestCanonicalMigration, ledgerState: "verified", identityState: "unknown"},
		{name: "missing identity singleton", ledger: true, identity: true, ledgerRow: true, version: LatestCanonicalMigration, ledgerState: "verified", identityState: "unknown"},
		{name: "verified", ledger: true, identity: true, ledgerRow: true, identityRow: true, version: LatestCanonicalMigration, ledgerState: "verified", identityState: "present"},
		{name: "dirty", ledger: true, identity: true, ledgerRow: true, identityRow: true, dirty: true, version: LatestCanonicalMigration, ledgerState: "dirty", identityState: "present"},
		{name: "wrong version", ledger: true, identity: true, ledgerRow: true, identityRow: true, version: LatestCanonicalMigration - 1, ledgerState: "incomplete", identityState: "present"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			connection, mock, err := sqlmock.New(sqlmock.MonitorPingsOption(true))
			if err != nil {
				t.Fatal(err)
			}
			defer connection.Close()
			db, err := gorm.Open(postgres.New(postgres.Config{Conn: connection}), &gorm.Config{DisableAutomaticPing: true, Logger: logger.Default.LogMode(logger.Silent)})
			if err != nil {
				t.Fatal(err)
			}
			mock.ExpectQuery("SELECT to_regclass").WillReturnRows(sqlmock.NewRows([]string{"ledger_exists", "identity_exists"}).AddRow(tc.ledger, tc.identity))
			if tc.ledger {
				rows := sqlmock.NewRows([]string{"version", "dirty", "identity_present", "database_id", "lineage_root_id", "database_epoch"})
				if tc.ledgerRow {
					if tc.identityRow {
						rows.AddRow(tc.version, tc.dirty, true, "database", "root", 3)
					} else {
						rows.AddRow(tc.version, tc.dirty, false, nil, nil, nil)
					}
				}
				query := "SELECT m.version, m.dirty, FALSE, NULL::text"
				if tc.identity {
					query = "SELECT m.version, m.dirty, i.singleton IS NOT NULL"
				}
				mock.ExpectQuery(query).WillReturnRows(rows)
			}
			got, err := ReadHealthContract(db)
			if err != nil {
				t.Fatal(err)
			}
			want := Contract{LedgerState: tc.ledgerState, IdentityState: tc.identityState, MigrationVersion: tc.version, EnforcementMode: "observe"}
			if tc.identityRow {
				want.DatabaseID, want.LineageRootID, want.Epoch = "database", "root", 3
			}
			if got != want {
				t.Fatalf("contract = %+v, want %+v", got, want)
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Fatal(err)
			}
		})
	}
}
