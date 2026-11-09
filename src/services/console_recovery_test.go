package services

import (
	"strings"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/yourusername/iam-authorization-service/src/config"
	"github.com/yourusername/iam-authorization-service/src/repository"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

type captureResetEmail struct{ body string }

func (m *captureResetEmail) Send(_, _, body string) error {
	m.body = body
	return nil
}

func TestConsolePasswordResetKeepsConsumerLinkDestination(t *testing.T) {
	for _, console := range []bool{true, false} {
		connection, mock, err := sqlmock.New()
		if err != nil {
			t.Fatal(err)
		}
		defer connection.Close()
		db, err := gorm.Open(postgres.New(postgres.Config{Conn: connection}), &gorm.Config{DisableAutomaticPing: true})
		if err != nil {
			t.Fatal(err)
		}
		mock.ExpectQuery(`SELECT .*FROM "users"`).WillReturnRows(sqlmock.NewRows([]string{"id", "email"}).
			AddRow("54ad2bc1-c8d9-4a63-99d5-ab855be8d211", "operator@example.test"))
		mock.ExpectBegin()
		mock.ExpectExec(`DELETE FROM "password_resets"`).WillReturnResult(sqlmock.NewResult(0, 1))
		mock.ExpectCommit()
		mock.ExpectBegin()
		mock.ExpectExec(`INSERT INTO "password_resets"`).WillReturnResult(sqlmock.NewResult(0, 1))
		mock.ExpectCommit()
		mail := &captureResetEmail{}
		cfg := &config.Config{
			Email:       config.EmailConfig{ResetBaseURL: "https://wahb.salehspace.dev"},
			ConsoleAuth: config.ConsoleAuthConfig{Origin: "https://wahb-console.salehspace.dev", Recovery: true},
		}
		service := NewPasswordResetService(repository.NewPasswordResetRepository(db), repository.NewUserRepository(db),
			repository.NewTokenRepository(db), mail, cfg)
		if err := service.ForgotPassword("operator@example.test", console); err != nil {
			t.Fatal(err)
		}
		expected := "https://wahb.salehspace.dev/reset-password?token="
		if console {
			expected = "https://wahb-console.salehspace.dev/reset-password#token="
		}
		if !strings.Contains(mail.body, expected) {
			t.Fatal("reset email used the wrong destination")
		}
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Fatal(err)
		}
	}
}
