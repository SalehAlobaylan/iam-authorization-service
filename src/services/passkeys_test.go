package services

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/fxamacker/cbor/v2"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/gofrs/uuid"
	"github.com/yourusername/iam-authorization-service/src/models"
	"github.com/yourusername/iam-authorization-service/src/utils"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

func TestConsolePasskeyVerifiesOriginAndUserVerification(t *testing.T) {
	const expectedOrigin = "http://localhost:3005"
	engine, err := newPasskeyEngine(expectedOrigin)
	if err != nil {
		t.Fatal(err)
	}
	_, session, err := engine.BeginDiscoverableLogin(webauthn.WithUserVerification(protocol.VerificationRequired))
	if err != nil {
		t.Fatal(err)
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	// A COSE EC2 ES256 public key as stored after a WebAuthn registration.
	public, err := cbor.Marshal(map[int]any{1: 2, 3: -7, -1: 1,
		-2: key.X.FillBytes(make([]byte, 32)), -3: key.Y.FillBytes(make([]byte, 32))})
	if err != nil {
		t.Fatal(err)
	}
	credential := webauthn.Credential{
		ID: []byte("fixture-passkey"), PublicKey: public,
		Flags: webauthn.NewCredentialFlags(protocol.FlagUserPresent | protocol.FlagUserVerified),
	}
	user := passkeyUser{
		account:     &models.User{ID: uuid.Must(uuid.NewV4()), Email: "operator@example.test"},
		credentials: []webauthn.Credential{credential},
	}
	for _, test := range []struct {
		name      string
		origin    string
		verified  bool
		wantError bool
	}{
		{"valid assertion", expectedOrigin, true, false},
		{"wrong origin", "https://other.example.test", true, true},
		{"missing user verification", expectedOrigin, false, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			client, err := json.Marshal(map[string]any{
				"type": "webauthn.get", "challenge": session.Challenge, "origin": test.origin,
			})
			if err != nil {
				t.Fatal(err)
			}
			rp := sha256.Sum256([]byte("localhost"))
			flags := protocol.FlagUserPresent
			if test.verified {
				flags |= protocol.FlagUserVerified
			}
			authenticator := append(rp[:], byte(flags), 0, 0, 0, 1)
			clientHash := sha256.Sum256(client)
			signed := sha256.Sum256(append(append([]byte{}, authenticator...), clientHash[:]...))
			signature, err := ecdsa.SignASN1(rand.Reader, key, signed[:])
			if err != nil {
				t.Fatal(err)
			}
			encode := base64.RawURLEncoding.EncodeToString
			data, err := json.Marshal(map[string]any{
				"id": encode(credential.ID), "rawId": encode(credential.ID), "type": "public-key",
				"response": map[string]string{
					"clientDataJSON": encode(client), "authenticatorData": encode(authenticator),
					"userHandle": encode(user.WebAuthnID()), "signature": encode(signature),
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			parsed, err := protocol.ParseCredentialRequestResponseBytes(data)
			if err != nil {
				t.Fatal(err)
			}
			_, _, err = engine.ValidatePasskeyLogin(func(_, _ []byte) (webauthn.User, error) {
				return user, nil
			}, *session, parsed)
			if (err != nil) != test.wantError {
				t.Fatalf("unexpected verification result: %v", err)
			}
		})
	}
}

func TestConsolePasskeyChallengeCanBeConsumedOnce(t *testing.T) {
	connection, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	db, err := gorm.Open(postgres.New(postgres.Config{Conn: connection}), &gorm.Config{DisableAutomaticPing: true})
	if err != nil {
		t.Fatal(err)
	}
	engine, err := newPasskeyEngine("http://localhost:3005")
	if err != nil {
		t.Fatal(err)
	}
	passkeys := Passkeys{db: db, rpID: engine.Config.RPID, webauthn: engine}
	binding := make([]byte, 32)
	digest := sha256.Sum256(binding)
	encoded := base64.RawURLEncoding.EncodeToString(binding)
	query := "DELETE FROM console_passkey_challenges .* expires_at > now\\(\\) RETURNING payload"
	mock.ExpectQuery(query).WithArgs(digest[:], "authentication", "localhost", nil).
		WillReturnRows(sqlmock.NewRows([]string{"payload"}).AddRow([]byte(`{"challenge":"fixture"}`)))
	mock.ExpectQuery(query).WithArgs(digest[:], "authentication", "localhost", nil).
		WillReturnRows(sqlmock.NewRows([]string{"payload"}))
	session, err := passkeys.takeChallenge(context.Background(), "authentication", encoded, nil)
	if err != nil || session.Challenge != "fixture" {
		t.Fatalf("consume challenge: %v", err)
	}
	_, err = passkeys.takeChallenge(context.Background(), "authentication", encoded, nil)
	if e, ok := utils.AsAPIError(err); !ok || e.StatusCode != 400 {
		t.Fatalf("replayed challenge was not rejected: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}
