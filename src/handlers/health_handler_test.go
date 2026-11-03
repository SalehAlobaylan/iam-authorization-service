package handlers

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/gin-gonic/gin"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func healthFixture(t *testing.T, deletionReady bool) (*gin.Engine, sqlmock.Sqlmock) {
	t.Helper()
	connection, mock, err := sqlmock.New(sqlmock.MonitorPingsOption(true))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { connection.Close() })
	db, err := gorm.Open(postgres.New(postgres.Config{Conn: connection}), &gorm.Config{DisableAutomaticPing: true, Logger: logger.Default.LogMode(logger.Silent)})
	if err != nil {
		t.Fatal(err)
	}
	router := gin.New()
	router.GET("/health", NewHealthHandler(db, func() bool { return deletionReady }).Health)
	return router, mock
}

func TestHealthUsesReadsAsConnectionProof(t *testing.T) {
	for _, tc := range []struct {
		name, mode           string
		readError, pingError bool
		deletionReady        bool
		status               int
	}{
		{"ready observe", "observe", false, false, true, http.StatusOK},
		{"ready enforce", "enforce", false, false, true, http.StatusOK},
		{"observe contract error still needs ping", "observe", true, false, true, http.StatusOK},
		{"observe cannot hide unreachable database", "observe", true, true, true, http.StatusServiceUnavailable},
		{"enforce rejects contract error", "enforce", true, false, true, http.StatusServiceUnavailable},
		{"deletion worker unavailable", "observe", false, false, false, http.StatusServiceUnavailable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("IAM_DATABASE_CONTRACT_MODE", tc.mode)
			t.Setenv("IAM_EXPECTED_DATABASE_ID", "database")
			t.Setenv("IAM_EXPECTED_DATABASE_EPOCH", "3")
			router, mock := healthFixture(t, tc.deletionReady)
			existence := mock.ExpectQuery("SELECT to_regclass")
			if tc.readError {
				existence.WillReturnError(errors.New("contract read failed"))
				ping := mock.ExpectPing()
				if tc.pingError {
					ping.WillReturnError(errors.New("database unavailable"))
				}
			} else {
				existence.WillReturnRows(sqlmock.NewRows([]string{"ledger_exists", "identity_exists"}).AddRow(true, true))
				mock.ExpectQuery("SELECT m.version").WillReturnRows(sqlmock.NewRows([]string{"version", "dirty", "identity_present", "database_id", "lineage_root_id", "database_epoch"}).AddRow(19, false, true, "database", "root", 3))
			}
			response := httptest.NewRecorder()
			router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/health", nil))
			if response.Code != tc.status {
				t.Fatalf("HTTP %d, want %d: %s", response.Code, tc.status, response.Body)
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestHealthCancelsDatabaseReadWithRequest(t *testing.T) {
	t.Setenv("IAM_DATABASE_CONTRACT_MODE", "observe")
	router, mock := healthFixture(t, true)
	mock.ExpectQuery("SELECT to_regclass").WillDelayFor(time.Second).
		WillReturnRows(sqlmock.NewRows([]string{"ledger_exists", "identity_exists"}).AddRow(true, true))
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	response := httptest.NewRecorder()
	start := time.Now()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/health", nil).WithContext(ctx))
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("cancelled request returned HTTP %d", response.Code)
	}
	if elapsed := time.Since(start); elapsed >= 500*time.Millisecond {
		t.Fatalf("request cancellation did not stop database work: %s", elapsed)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}
