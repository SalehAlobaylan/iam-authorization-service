// env-migrate is the offline canonical IAM owner. It retains golang-migrate's
// version/dirty protocol and adds transaction-bound target checks.
package main

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/postgres"
	"github.com/golang-migrate/migrate/v4/source"
	"github.com/golang-migrate/migrate/v4/source/file"
	"io"
	"log"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

type checkedSource struct {
	source.Driver
	dir             string
	hashes          map[string]string
	allowed         map[string]bool
	startingVersion int64
}

func (s checkedSource) ReadUp(version uint) (io.ReadCloser, string, error) {
	r, id, e := s.Driver.ReadUp(version)
	if e != nil {
		return nil, id, e
	}
	defer r.Close()
	b, e := io.ReadAll(r)
	if e != nil {
		return nil, id, e
	}
	name := fmt.Sprintf("%06d_%s.up.sql", version, id)
	currentVersionProbe := s.startingVersion > 0 && int64(version) == s.startingVersion
	if !s.allowed[name] && !currentVersionProbe {
		return nil, id, fmt.Errorf("IAM next file changed after review: %s", name)
	}
	sum := sha256.Sum256(b)
	if s.hashes[name] != hex.EncodeToString(sum[:]) {
		return nil, id, fmt.Errorf("IAM migration bytes changed after review: %s", name)
	}
	if currentVersionProbe {
		// golang-migrate reads the current version solely to check existence
		// before moving up. Supply an empty, checksum-checked probe body;
		// the already-applied SQL is never exposed for execution.
		return io.NopCloser(strings.NewReader("")), id, nil
	}
	guard, err := preparationGuard()
	if err != nil {
		return nil, id, err
	}
	return io.NopCloser(strings.NewReader("BEGIN;\nSET LOCAL lock_timeout='10s';\n" + guard + "\n" + string(b) + "\nCOMMIT;")), id, nil
}
func preparationGuard() (string, error) {
	expected := os.Getenv("WAHB_PREPARATION_DATABASE_ID")
	epoch := os.Getenv("WAHB_PREPARATION_DATABASE_EPOCH")
	if expected != "absent" && !regexp.MustCompile(`^[a-f0-9-]{36}$`).MatchString(expected) {
		return "", fmt.Errorf("invalid reviewed identity")
	}
	if !regexp.MustCompile(`^\d+$`).MatchString(epoch) {
		return "", fmt.Errorf("invalid reviewed epoch")
	}
	guard := fmt.Sprintf(`DO $localguard$
DECLARE observed_id text; observed_epoch bigint; fence_state text; fence_epoch bigint; owner_state text;
BEGIN
 IF to_regclass('public.wahb_database_identity') IS NOT NULL THEN
  LOCK TABLE wahb_database_identity IN SHARE MODE;
  SELECT database_id::text,database_epoch INTO observed_id,observed_epoch FROM wahb_database_identity WHERE singleton=TRUE FOR SHARE;
  IF ('%s'='absent' AND observed_id IS NOT NULL) OR ('%s'<>'absent' AND (observed_id IS DISTINCT FROM '%s' OR observed_epoch IS DISTINCT FROM %s)) THEN RAISE EXCEPTION 'IAM identity changed after review'; END IF;
 ELSIF '%s'<>'absent' THEN RAISE EXCEPTION 'IAM identity is missing'; END IF;
 IF to_regclass('public.wahb_database_writer_fence') IS NOT NULL THEN
  SELECT state,epoch INTO fence_state,fence_epoch FROM wahb_database_writer_fence WHERE singleton=TRUE FOR SHARE;
  IF fence_state IS NULL OR fence_state NOT IN ('open','successor_open') OR (observed_id IS NOT NULL AND fence_epoch IS DISTINCT FROM observed_epoch) THEN RAISE EXCEPTION 'IAM writes are fenced'; END IF;
 END IF;
 IF to_regclass('public.database_migration_owner_control') IS NOT NULL THEN
  SELECT state INTO owner_state FROM database_migration_owner_control WHERE singleton=TRUE FOR SHARE;
  IF owner_state IS DISTINCT FROM 'running' THEN RAISE EXCEPTION 'IAM relocation owner is quiesced'; END IF;
 END IF;
END $localguard$;`, expected, expected, expected, epoch, expected)
	return guard, nil
}

func main() {
	dir := flag.String("dir", "database-migrations/migrations", "frozen canonical migration directory")
	manifest := flag.String("manifest", "", "reviewed file checksum manifest")
	steps := flag.Int("steps", 1, "exact reviewed number of versions")
	expectedFiles := flag.String("files", "", "comma-separated exact reviewed filenames")
	expectedVersion := flag.Int64("expected-version", -1, "exact reviewed starting version; zero means no applied versions")
	flag.Parse()
	if os.Getenv("WAHB_LOCAL_PREPARATION") != "1" || *steps < 1 || *expectedVersion < 0 {
		log.Fatal("explicit local preparation is required")
	}
	b, e := os.ReadFile(*manifest)
	if e != nil {
		log.Fatal(e)
	}
	hashes := map[string]string{}
	if json.Unmarshal(b, &hashes) != nil {
		log.Fatal("invalid checksum manifest")
	}
	allowed := map[string]bool{}
	for _, name := range strings.Split(*expectedFiles, ",") {
		if hashes[name] == "" {
			log.Fatal("reviewed IAM file missing from manifest")
		}
		allowed[name] = true
	}
	absolute, e := filepath.Abs(*dir)
	if e != nil {
		log.Fatal(e)
	}
	d, e := (&file.File{}).Open("file://" + absolute)
	if e != nil {
		log.Fatal(e)
	}
	u, e := url.Parse(os.Getenv("DATABASE_URL"))
	if e != nil {
		log.Fatal("invalid IAM target")
	}

	guard, err := preparationGuard()
	if err != nil {
		log.Fatal(err)
	}
	guardDB, err := sql.Open("postgres", u.String())
	if err != nil {
		log.Fatal("IAM guard connection failed")
	}
	defer guardDB.Close()
	guardTx, err := guardDB.Begin()
	if err != nil {
		log.Fatal("IAM guard transaction failed")
	}
	defer guardTx.Rollback()
	if _, err = guardTx.Exec("SET LOCAL lock_timeout='10s'; " + guard); err != nil {
		log.Fatal("IAM authority changed before migration initialization")
	}
	// Initialize golang-migrate's own ledger under the same identity locks. Its
	// driver will see the existing table and perform no unguarded DDL.
	if _, err = guardTx.Exec("CREATE TABLE IF NOT EXISTS iam_schema_migrations (version bigint not null primary key, dirty boolean not null)"); err != nil {
		log.Fatal("IAM ledger initialization failed")
	}
	if err = guardTx.Commit(); err != nil {
		log.Fatal("IAM ledger initialization was not acknowledged")
	}

	q := u.Query()
	q.Set("x-migrations-table", "iam_schema_migrations")
	u.RawQuery = q.Encode()
	runner, e := migrate.NewWithSourceInstance("file", checkedSource{Driver: d, dir: absolute, hashes: hashes, allowed: allowed, startingVersion: *expectedVersion}, u.String())
	if e != nil {
		log.Fatal("IAM migration initialization failed")
	}
	defer runner.Close()
	version, dirty, e := runner.Version()
	if e != nil && e != migrate.ErrNilVersion {
		log.Fatal("IAM migration ledger could not be read")
	}
	if dirty {
		log.Fatalf("IAM ledger is dirty at %d; owner recovery is required", version)
	}
	observedVersion := int64(version)
	if e == migrate.ErrNilVersion {
		observedVersion = 0
	}
	if observedVersion != *expectedVersion {
		log.Fatal("IAM version changed after review; inspect before continuing")
	}
	if e = runner.Steps(*steps); e != nil && e != migrate.ErrNoChange {
		log.Fatal(e)
	}
	version, dirty, e = runner.Version()
	if e != nil || dirty {
		log.Fatal("IAM post-migration ledger verification failed")
	}
	fmt.Println("IAM verified version", version)
}
