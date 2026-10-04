package main

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/database/stub"
	"github.com/golang-migrate/migrate/v4/source/file"
)

func TestReviewedSourceRejectsEditedAndUnapprovedFiles(t *testing.T) {
	dir := t.TempDir()
	name := "000001_reviewed.up.sql"
	original := []byte("CREATE TABLE example(id bigint);")
	if err := os.WriteFile(filepath.Join(dir, name), original, 0600); err != nil {
		t.Fatal(err)
	}
	driver, err := (&file.File{}).Open("file://" + dir)
	if err != nil {
		t.Fatal(err)
	}
	defer driver.Close()
	sum := sha256.Sum256(original)
	source := checkedSource{Driver: driver, hashes: map[string]string{name: hex.EncodeToString(sum[:])}, allowed: map[string]bool{}}
	if _, _, err = source.ReadUp(1); err == nil {
		t.Fatal("unreviewed file accepted")
	}
	source.allowed[name] = true
	if err = os.WriteFile(filepath.Join(dir, name), []byte("DROP TABLE example;"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, _, err = source.ReadUp(1); err == nil {
		t.Fatal("changed file accepted before effect")
	}
}

func TestUpgradeProbesCurrentVersionWithoutReplayingIt(t *testing.T) {
	t.Setenv("WAHB_PREPARATION_DATABASE_ID", "absent")
	t.Setenv("WAHB_PREPARATION_DATABASE_EPOCH", "0")
	dir := t.TempDir()
	files := map[string]string{
		"000017_current.up.sql":    "SELECT 'NEVER_REPLAY_VERSION_17';",
		"000018_reviewed.up.sql":   "SELECT 'REVIEWED_VERSION_18';",
		"000019_unreviewed.up.sql": "SELECT 'UNREVIEWED_VERSION_19';",
	}
	hashes := map[string]string{}
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256([]byte(body))
		hashes[name] = hex.EncodeToString(sum[:])
	}
	driver, err := (&file.File{}).Open("file://" + dir)
	if err != nil {
		t.Fatal(err)
	}
	source := checkedSource{Driver: driver, hashes: hashes, allowed: map[string]bool{"000018_reviewed.up.sql": true}, startingVersion: 17}
	database := &stub.Stub{CurrentVersion: 17}
	runner, err := migrate.NewWithInstance("file", source, "stub", database)
	if err != nil {
		t.Fatal(err)
	}
	defer runner.Close()
	if err := runner.Steps(1); err != nil {
		t.Fatal(err)
	}
	if database.CurrentVersion != 18 || database.IsDirty || len(database.MigrationSequence) != 1 {
		t.Fatalf("wrong version transition: %+v", database)
	}
	body := string(database.LastRunMigration)
	if !strings.Contains(body, "REVIEWED_VERSION_18") || strings.Contains(body, "NEVER_REPLAY_VERSION_17") || strings.Contains(body, "UNREVIEWED_VERSION_19") {
		t.Fatal(body)
	}
	if _, _, err := source.ReadUp(19); err == nil {
		t.Fatal("unreviewed next version was exposed")
	}
	probe, _, err := source.ReadUp(17)
	if err != nil {
		t.Fatal(err)
	}
	defer probe.Close()
	b, err := io.ReadAll(probe)
	if err != nil || len(b) != 0 {
		t.Fatalf("applied SQL was exposed: %q, %v", b, err)
	}
	if err := os.WriteFile(filepath.Join(dir, "000017_current.up.sql"), []byte("changed"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := source.ReadUp(17); err == nil {
		t.Fatal("modified current-version probe accepted")
	}
}
func TestGuardRejectsUntrustedIdentityAndEpoch(t *testing.T) {
	t.Setenv("WAHB_PREPARATION_DATABASE_ID", "absent")
	t.Setenv("WAHB_PREPARATION_DATABASE_EPOCH", "0; DROP TABLE users")
	if _, err := preparationGuard(); err == nil {
		t.Fatal("SQL-like epoch accepted")
	}
	t.Setenv("WAHB_PREPARATION_DATABASE_EPOCH", "0")
	t.Setenv("WAHB_PREPARATION_DATABASE_ID", "'; DROP TABLE users; --")
	if _, err := preparationGuard(); err == nil {
		t.Fatal("SQL-like identity accepted")
	}
}
