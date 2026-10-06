package passkeys

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strconv"
	"time"
	"uuid"

	"github.com/mehmetcagriekici/learn-web-security-golang-starter/internal/accounts"
	"github.com/mehmetcagriekici/learn-web-security-golang-starter/internal/database/dbgen"
	"github.com/go-webauthn/webauthn/protocol"
	webauthn "github.com/go-webauthn/webauthn/webauthn"
)

type Credential struct {
	ID           int64
	CredentialID string
	CreatedAt    string
}

type Challenge struct {
	ID          uuid.UUID
	UserID      *int64
	SessionData webauthn.SessionData
}

type User struct {
	account     accounts.User
	credentials []webauthn.Credential
}

func (user User) WebAuthnID() []byte {
	return []byte(strconv.FormatInt(user.account.ID, 10))
}

func (user User) WebAuthnName() string {
	return user.account.Email
}

func (user User) WebAuthnDisplayName() string {
	return user.account.DisplayName
}

func (user User) WebAuthnCredentials() []webauthn.Credential {
	return user.credentials
}

type Store struct {
	queries *dbgen.Queries
	now     func() time.Time
}

func NewStore(database *sql.DB) *Store {
	return &Store{queries: dbgen.New(database), now: time.Now}
}

func (store *Store) ListCredentials(ctx context.Context, userID int64) ([]Credential, error) {
	rows, err := store.queries.ListPasskeyCredentials(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("list passkey credentials: %w", err)
	}
	credentials := make([]Credential, 0, len(rows))
	for _, row := range rows {
		credentials = append(credentials, Credential{ID: row.ID, CredentialID: row.CredentialID, CreatedAt: row.CreatedAt})
	}
	return credentials, nil
}

func (store *Store) User(ctx context.Context, account accounts.User) (User, error) {
	rows, err := store.queries.ListPasskeyCredentials(ctx, account.ID)
	if err != nil {
		return User{}, fmt.Errorf("list user passkey credentials: %w", err)
	}
	credentials := make([]webauthn.Credential, 0, len(rows))
	for _, row := range rows {
		credential, err := webAuthnCredential(row)
		if err != nil {
			return User{}, err
		}
		credentials = append(credentials, credential)
	}
	return User{account: account, credentials: credentials}, nil
}

func (store *Store) CredentialAccountID(ctx context.Context, credentialID string) (int64, bool, error) {
	row, err := store.queries.GetPasskeyCredentialByCredentialID(ctx, credentialID)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, fmt.Errorf("find passkey credential: %w", err)
	}
	return row.UserID, true, nil
}

func (store *Store) CreateChallenge(ctx context.Context, userID *int64, sessionData webauthn.SessionData) (Challenge, error) {
	now := store.now().UTC()
	if err := store.queries.DeleteExpiredPasskeyChallenges(ctx, formatTimestamp(now)); err != nil {
		return Challenge{}, fmt.Errorf("delete expired passkey challenges: %w", err)
	}
	identifier := uuid.NewV4()
	serializedSession, err := json.Marshal(sessionData)
	if err != nil {
		return Challenge{}, fmt.Errorf("serialize passkey session data: %w", err)
	}
	if err := store.queries.CreatePasskeyChallenge(ctx, dbgen.CreatePasskeyChallengeParams{
		ID: identifier.String(), Challenge: sessionData.Challenge, UserID: userID, SessionData: string(serializedSession),
		ExpiresAt: formatTimestamp(sessionData.Expires), CreatedAt: formatTimestamp(now),
	}); err != nil {
		return Challenge{}, fmt.Errorf("create passkey challenge: %w", err)
	}
	return Challenge{ID: identifier, UserID: userID, SessionData: sessionData}, nil
}

func (store *Store) ConsumeChallenge(ctx context.Context, identifier uuid.UUID) (Challenge, bool, error) {
	row, err := store.queries.ConsumePasskeyChallenge(ctx, identifier.String())
	if errors.Is(err, sql.ErrNoRows) {
		return Challenge{}, false, nil
	}
	if err != nil {
		return Challenge{}, false, fmt.Errorf("consume passkey challenge: %w", err)
	}
	expiresAt, err := time.Parse(time.RFC3339, row.ExpiresAt)
	if err != nil || !store.now().Before(expiresAt) {
		return Challenge{}, false, nil
	}
	var sessionData webauthn.SessionData
	if err := json.Unmarshal([]byte(row.SessionData), &sessionData); err != nil {
		return Challenge{}, false, fmt.Errorf("decode passkey session data: %w", err)
	}
	return Challenge{ID: identifier, UserID: row.UserID, SessionData: sessionData}, true, nil
}

func (store *Store) StoreCredential(ctx context.Context, userID int64, credential webauthn.Credential) error {
	transports, err := json.Marshal(credential.Transport)
	if err != nil {
		return fmt.Errorf("serialize passkey transports: %w", err)
	}
	transportsValue := string(transports)
	if len(credential.Transport) == 0 {
		transportsValue = ""
	}
	var storedTransports *string
	if transportsValue != "" {
		storedTransports = &transportsValue
	}
	if err := store.queries.CreatePasskeyCredential(ctx, dbgen.CreatePasskeyCredentialParams{
		UserID: userID, CredentialID: encodeBase64URL(credential.ID), PublicKey: encodeBase64URL(credential.PublicKey),
		Counter: int64(credential.Authenticator.SignCount), Transports: storedTransports,
	}); err != nil {
		return fmt.Errorf("store passkey credential: %w", err)
	}
	return nil
}

func (store *Store) UpdateCounter(ctx context.Context, credential webauthn.Credential) error {
	if err := store.queries.UpdatePasskeyCredentialCounter(ctx, dbgen.UpdatePasskeyCredentialCounterParams{
		Counter: int64(credential.Authenticator.SignCount), CredentialID: encodeBase64URL(credential.ID),
	}); err != nil {
		return fmt.Errorf("update passkey counter: %w", err)
	}
	return nil
}

func (store *Store) DeleteCredential(ctx context.Context, credentialID, userID int64) error {
	if err := store.queries.DeletePasskeyCredential(ctx, dbgen.DeletePasskeyCredentialParams{ID: credentialID, UserID: userID}); err != nil {
		return fmt.Errorf("delete passkey credential: %w", err)
	}
	return nil
}

func webAuthnCredential(row dbgen.PasskeyCredential) (webauthn.Credential, error) {
	if row.Counter < 0 || row.Counter > math.MaxUint32 {
		return webauthn.Credential{}, fmt.Errorf("invalid passkey signature counter")
	}
	credentialID, err := decodeBase64URL(row.CredentialID)
	if err != nil {
		return webauthn.Credential{}, fmt.Errorf("decode passkey credential ID: %w", err)
	}
	publicKey, err := decodeBase64URL(row.PublicKey)
	if err != nil {
		return webauthn.Credential{}, fmt.Errorf("decode passkey public key: %w", err)
	}
	transports := []protocol.AuthenticatorTransport{}
	if row.Transports != nil {
		if err := json.Unmarshal([]byte(*row.Transports), &transports); err != nil {
			return webauthn.Credential{}, fmt.Errorf("decode passkey transports: %w", err)
		}
	}
	return webauthn.Credential{
		ID: credentialID, PublicKey: publicKey, Transport: transports,
		Authenticator: webauthn.Authenticator{SignCount: uint32(row.Counter)},
	}, nil
}

func decodeBase64URL(value string) ([]byte, error) {
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	if err == nil {
		return decoded, nil
	}
	return base64.URLEncoding.DecodeString(value)
}

func encodeBase64URL(value []byte) string {
	return base64.RawURLEncoding.EncodeToString(value)
}

func formatTimestamp(timestamp time.Time) string {
	return timestamp.UTC().Format("2006-01-02T15:04:05.000Z")
}
