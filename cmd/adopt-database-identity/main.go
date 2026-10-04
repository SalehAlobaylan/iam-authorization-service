package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/yourusername/iam-authorization-service/src/config"
	"github.com/yourusername/iam-authorization-service/src/database"
	"gorm.io/gorm"
	"log"
	"os"
	"regexp"
)

func main() {
	id := flag.String("id", "", "reviewed new database identity")
	schema := flag.String("schema", "", "exact schema fingerprint from offline review")
	actor := flag.String("actor", "", "local operator identity")
	flag.Parse()
	if os.Getenv("WAHB_LOCAL_PREPARATION") != "1" || !regexp.MustCompile(`^[a-f0-9-]{36}$`).MatchString(*id) || *actor == "" {
		log.Fatal("identity adoption requires explicit managed preparation review")
	}
	db, err := database.NewPostgres(config.DatabaseConfig{URL: os.Getenv("DATABASE_URL"), PreferSimpleProtocol: true})
	if err != nil {
		log.Fatal(err)
	}
	err = db.Transaction(func(tx *gorm.DB) error {
		var schemaRows []struct {
			TableName  string
			ColumnName string
			UDTName    string
		}
		if e := tx.Raw("SELECT cols.table_name,cols.column_name,pg_catalog.format_type(a.atttypid,a.atttypmod) AS udt_name FROM information_schema.columns cols JOIN pg_namespace n ON n.nspname=cols.table_schema JOIN pg_class c ON c.relnamespace=n.oid AND c.relname=cols.table_name JOIN pg_attribute a ON a.attrelid=c.oid AND a.attname=cols.column_name WHERE cols.table_schema='public' ORDER BY cols.table_name,cols.ordinal_position").Scan(&schemaRows).Error; e != nil {
			return e
		}
		values := []string{}
		for _, r := range schemaRows {
			values = append(values, r.TableName+"."+r.ColumnName+":"+r.UDTName)
		}
		b, _ := json.Marshal(values)
		sum := sha256.Sum256(b)
		if hex.EncodeToString(sum[:]) != *schema {
			return fmt.Errorf("schema changed after identity review")
		}
		var ownerState string
		if e := tx.Raw("SELECT state FROM database_migration_owner_control WHERE singleton=TRUE FOR SHARE").Scan(&ownerState).Error; e != nil {
			return e
		}
		if ownerState != "running" {
			return fmt.Errorf("relocation owner has quiesced writes")
		}
		var existing int64
		if e := tx.Exec("LOCK TABLE wahb_database_identity IN EXCLUSIVE MODE").Error; e != nil {
			return e
		}
		if e := tx.Table("wahb_database_identity").Count(&existing).Error; e != nil {
			return e
		}
		if existing != 0 {
			return fmt.Errorf("identity already assigned; automatic adoption is refused")
		}
		var fence string
		if e := tx.Raw("SELECT state FROM wahb_database_writer_fence WHERE singleton=TRUE FOR SHARE").Scan(&fence).Error; e != nil {
			return e
		}
		if fence != "open" {
			return fmt.Errorf("identity adoption requires an open epoch-zero fence")
		}
		var epoch int64
		if e := tx.Raw("SELECT epoch FROM wahb_database_writer_fence WHERE singleton=TRUE").Scan(&epoch).Error; e != nil {
			return e
		}
		if epoch != 0 {
			return fmt.Errorf("identity adoption requires epoch zero")
		}
		c, e := database.ReadContract(tx)
		if e != nil {
			return e
		}
		if c.LedgerState != "verified" {
			return fmt.Errorf("canonical IAM ledger must be verified before adoption")
		}
		if e := tx.Exec("INSERT INTO wahb_database_identity(singleton,database_id,lineage_root_id,database_epoch,schema_contract_version) VALUES(TRUE,?, ?,0,?)", *id, *id, "iam/v1").Error; e != nil {
			return e
		}
		evidence, _ := json.Marshal(map[string]string{"actor": *actor, "schema": *schema, "operation": "explicit_local_identity_adoption"})
		return tx.Exec("INSERT INTO wahb_database_identity_events(database_id,lineage_root_id,database_epoch,event_type,evidence) VALUES(?,?,0,'local_identity_adopted',?::jsonb)", *id, *id, string(evidence)).Error
	})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("Reviewed identity adopted")
}
