package services

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/yourusername/iam-authorization-service/src/models"
	"github.com/yourusername/iam-authorization-service/src/repository"
	"github.com/yourusername/iam-authorization-service/src/utils"
	"gorm.io/gorm"
)

const passkeyLifetime = 5 * time.Minute

type Passkeys struct {
	db       *gorm.DB
	auth     *AuthService
	webauthn *webauthn.WebAuthn
	rpID     string
}

type PasskeySummary struct {
	ID         string     `json:"id"`
	CreatedAt  time.Time  `json:"created_at"`
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`
}

type storedPasskey struct {
	CredentialID []byte
	UserID       string
	Credential   []byte
	CreatedAt    time.Time
	LastUsedAt   *time.Time
}

type passkeyUser struct {
	account     *models.User
	credentials []webauthn.Credential
}

func (u passkeyUser) WebAuthnID() []byte                         { return u.account.ID.Bytes() }
func (u passkeyUser) WebAuthnName() string                       { return u.account.Email }
func (u passkeyUser) WebAuthnDisplayName() string                { return u.account.Email }
func (u passkeyUser) WebAuthnCredentials() []webauthn.Credential { return u.credentials }

func NewPasskeys(db *gorm.DB, auth *AuthService, origin string) (*Passkeys, error) {
	engine, err := newPasskeyEngine(origin)
	if err != nil {
		return nil, err
	}
	if !db.Migrator().HasTable("console_passkeys") || !db.Migrator().HasTable("console_passkey_challenges") {
		return nil, errors.New("Console passkey migration is required")
	}
	return &Passkeys{db: db, auth: auth, webauthn: engine, rpID: engine.Config.RPID}, nil
}

func newPasskeyEngine(origin string) (*webauthn.WebAuthn, error) {
	parsed, err := url.Parse(origin)
	if err != nil || parsed.Hostname() == "" {
		return nil, errors.New("invalid Console passkey origin")
	}
	rpID := parsed.Hostname()
	timeout := webauthn.TimeoutConfig{Enforce: true, Timeout: passkeyLifetime, TimeoutUVD: passkeyLifetime}
	return webauthn.New(&webauthn.Config{
		RPID: rpID, RPDisplayName: "Wahb Platform Console", RPOrigins: []string{origin},
		AttestationPreference: protocol.PreferNoAttestation,
		AuthenticatorSelection: protocol.AuthenticatorSelection{
			ResidentKey:      protocol.ResidentKeyRequirementRequired,
			UserVerification: protocol.VerificationRequired,
		},
		Timeouts: webauthn.TimeoutsConfig{Login: timeout, Registration: timeout},
	})
}

func (p *Passkeys) list(ctx context.Context, userID string) ([]storedPasskey, error) {
	var rows []storedPasskey
	err := p.db.WithContext(ctx).Table("console_passkeys").
		Where("user_id = ? AND rp_id = ?", userID, p.rpID).
		Order("created_at DESC").Find(&rows).Error
	return rows, err
}

func (p *Passkeys) List(ctx context.Context, userID string) ([]PasskeySummary, error) {
	rows, err := p.list(ctx, userID)
	if err != nil {
		return nil, err
	}
	result := make([]PasskeySummary, 0, len(rows))
	for _, row := range rows {
		result = append(result, PasskeySummary{ID: base64.RawURLEncoding.EncodeToString(row.CredentialID), CreatedAt: row.CreatedAt, LastUsedAt: row.LastUsedAt})
	}
	return result, nil
}

func (p *Passkeys) account(userID string, password *string) (*models.User, error) {
	user, err := p.auth.userRepo.GetByID(userID)
	if errors.Is(err, repository.ErrUserNotFound) {
		return nil, utils.UnauthorizedError("passkey account unavailable")
	}
	if err != nil {
		return nil, err
	}
	if user.SuspendedAt != nil || (p.auth.config.Email.RequireVerification && !user.EmailVerified) {
		return nil, utils.UnauthorizedError("passkey account unavailable")
	}
	if password != nil && utils.ComparePassword(user.PasswordHash, *password) != nil {
		return nil, utils.UnauthorizedError("current password is incorrect")
	}
	return user, nil
}

func (p *Passkeys) registrationUser(ctx context.Context, userID string, password *string) (passkeyUser, error) {
	account, err := p.account(userID, password)
	if err != nil {
		return passkeyUser{}, err
	}
	rows, err := p.list(ctx, userID)
	if err != nil {
		return passkeyUser{}, err
	}
	user := passkeyUser{account: account}
	for _, row := range rows {
		var credential webauthn.Credential
		if err := json.Unmarshal(row.Credential, &credential); err != nil {
			return passkeyUser{}, err
		}
		user.credentials = append(user.credentials, credential)
	}
	return user, nil
}

func (p *Passkeys) saveChallenge(ctx context.Context, operation string, userID *string, session *webauthn.SessionData) (string, error) {
	payload, err := json.Marshal(session)
	if err != nil {
		return "", err
	}
	binding := make([]byte, 32)
	if _, err := rand.Read(binding); err != nil {
		return "", err
	}
	digest := sha256.Sum256(binding)
	db := p.db.WithContext(ctx)
	if err := db.Exec("DELETE FROM console_passkey_challenges WHERE expires_at <= now()").Error; err != nil {
		return "", err
	}
	err = db.Exec(`INSERT INTO console_passkey_challenges (digest, operation, user_id, rp_id, payload, expires_at)
		VALUES (?, ?, ?, ?, ?, ?)`, digest[:], operation, userID, p.rpID, payload, session.Expires).Error
	return base64.RawURLEncoding.EncodeToString(binding), err
}

func (p *Passkeys) takeChallenge(ctx context.Context, operation, binding string, userID *string) (webauthn.SessionData, error) {
	var session webauthn.SessionData
	raw, err := base64.RawURLEncoding.DecodeString(binding)
	if err != nil || len(raw) != 32 {
		return session, utils.ValidationError("passkey request expired")
	}
	digest := sha256.Sum256(raw)
	var row struct{ Payload []byte }
	result := p.db.WithContext(ctx).Raw(`DELETE FROM console_passkey_challenges
		WHERE digest = ? AND operation = ? AND rp_id = ? AND user_id IS NOT DISTINCT FROM CAST(? AS uuid)
		AND expires_at > now() RETURNING payload`, digest[:], operation, p.rpID, userID).Scan(&row)
	if result.Error != nil {
		return session, result.Error
	}
	if result.RowsAffected != 1 {
		return session, utils.ValidationError("passkey request expired")
	}
	return session, json.Unmarshal(row.Payload, &session)
}

func (p *Passkeys) BeginRegistration(ctx context.Context, userID, password string) (*protocol.CredentialCreation, string, error) {
	user, err := p.registrationUser(ctx, userID, &password)
	if err != nil {
		return nil, "", err
	}
	options, session, err := p.webauthn.BeginRegistration(user,
		webauthn.WithExclusions(webauthn.Credentials(user.credentials).CredentialDescriptors()))
	if err != nil {
		return nil, "", err
	}
	binding, err := p.saveChallenge(ctx, "registration", &userID, session)
	return options, binding, err
}

func (p *Passkeys) FinishRegistration(ctx context.Context, userID, binding string, response json.RawMessage) error {
	session, err := p.takeChallenge(ctx, "registration", binding, &userID)
	if err != nil {
		return err
	}
	user, err := p.registrationUser(ctx, userID, nil)
	if err != nil {
		return err
	}
	parsed, err := protocol.ParseCredentialCreationResponseBytes(response)
	if err != nil {
		return utils.ValidationError("passkey registration failed")
	}
	credential, err := p.webauthn.CreateCredential(user, session, parsed)
	if err != nil {
		return utils.ValidationError("passkey registration failed")
	}
	data, err := json.Marshal(credential)
	if err != nil {
		return err
	}
	result := p.db.WithContext(ctx).Exec(`INSERT INTO console_passkeys (credential_id, user_id, rp_id, credential)
		VALUES (?, ?, ?, ?) ON CONFLICT (credential_id) DO NOTHING`, credential.ID, userID, p.rpID, data)
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected != 1 {
		return utils.ValidationError("this passkey is already registered")
	}
	return nil
}

func (p *Passkeys) BeginAuthentication(ctx context.Context) (*protocol.CredentialAssertion, string, error) {
	options, session, err := p.webauthn.BeginDiscoverableLogin(webauthn.WithUserVerification(protocol.VerificationRequired))
	if err != nil {
		return nil, "", err
	}
	binding, err := p.saveChallenge(ctx, "authentication", nil, session)
	return options, binding, err
}

func (p *Passkeys) FinishAuthentication(ctx context.Context, binding string, response json.RawMessage) (*models.TokenPair, error) {
	session, err := p.takeChallenge(ctx, "authentication", binding, nil)
	if err != nil {
		return nil, err
	}
	parsed, err := protocol.ParseCredentialRequestResponseBytes(response)
	if err != nil {
		return nil, utils.UnauthorizedError("passkey sign-in failed")
	}
	var lookupErr error
	var prior []byte
	user, credential, err := p.webauthn.ValidatePasskeyLogin(func(rawID, handle []byte) (webauthn.User, error) {
		var row storedPasskey
		result := p.db.WithContext(ctx).Table("console_passkeys").
			Where("credential_id = ? AND rp_id = ?", rawID, p.rpID).Take(&row)
		if result.Error != nil {
			if !errors.Is(result.Error, gorm.ErrRecordNotFound) {
				lookupErr = result.Error
			}
			return nil, result.Error
		}
		account, err := p.account(row.UserID, nil)
		if err != nil {
			lookupErr = err
			return nil, err
		}
		if !bytes.Equal(handle, account.ID.Bytes()) {
			return nil, errors.New("passkey user handle mismatch")
		}
		var saved webauthn.Credential
		if err := json.Unmarshal(row.Credential, &saved); err != nil {
			lookupErr = err
			return nil, err
		}
		prior = row.Credential
		return passkeyUser{account: account, credentials: []webauthn.Credential{saved}}, nil
	}, session, parsed)
	if lookupErr != nil {
		return nil, lookupErr
	}
	if err != nil || credential.Authenticator.CloneWarning {
		return nil, utils.UnauthorizedError("passkey sign-in failed")
	}

	verified := user.(passkeyUser)
	data, err := json.Marshal(credential)
	if err != nil {
		return nil, err
	}
	result := p.db.WithContext(ctx).Exec(`UPDATE console_passkeys SET credential = ?, last_used_at = now()
		WHERE credential_id = ? AND user_id = ? AND rp_id = ? AND credential = ?`,
		data, credential.ID, verified.account.ID.String(), p.rpID, prior)
	if result.Error != nil {
		return nil, result.Error
	}
	if result.RowsAffected != 1 {
		return nil, utils.UnauthorizedError("passkey changed during sign-in")
	}
	return p.auth.issueLoginSession(verified.account)
}

func (p *Passkeys) Remove(ctx context.Context, userID, password, credentialID string) error {
	if _, err := p.account(userID, &password); err != nil {
		return err
	}
	id, err := base64.RawURLEncoding.DecodeString(credentialID)
	if err != nil || len(id) == 0 {
		return utils.ValidationError("invalid passkey")
	}
	if err := p.db.WithContext(ctx).Exec("DELETE FROM console_passkeys WHERE credential_id = ? AND user_id = ? AND rp_id = ?",
		id, userID, p.rpID).Error; err != nil {
		return fmt.Errorf("remove passkey: %w", err)
	}
	return nil
}
