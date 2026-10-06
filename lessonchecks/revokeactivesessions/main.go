package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/mehmetcagriekici/learn-web-security-golang-starter/internal/accounts"
	"github.com/mehmetcagriekici/learn-web-security-golang-starter/internal/database"
)

const originalRevocation = "2000-01-01T12:00:00.000Z"

type activeSessionRevoker interface {
	RevokeAllActiveSessions(context.Context) (int, error)
}

type probeSession struct {
	token     string
	createdAt time.Time
	revokedAt *string
}

type checkResult struct {
	Revoked                                 int  `json:"revoked"`
	OldSessionActive                        bool `json:"oldSessionActive"`
	BoundarySessionActive                   bool `json:"boundarySessionActive"`
	NewSessionActive                        bool `json:"newSessionActive"`
	RevocationTimestampMatchesDatabaseClock bool `json:"revocationTimestampMatchesDatabaseClock"`
	AlreadyRevokedSessionUnchanged          bool `json:"alreadyRevokedSessionUnchanged"`
	RepeatedRevocationMadeNoChanges         bool `json:"repeatRevocationNoChanges"`
}

func main() {
	result, err := checkEmergencySessionRevocation(context.Background())
	if err != nil {
		log.Fatal(err)
	}
	if err := json.NewEncoder(os.Stdout).Encode(result); err != nil {
		log.Fatal(err)
	}
}

func checkEmergencySessionRevocation(ctx context.Context) (checkResult, error) {
	temporaryDirectory, err := os.MkdirTemp("", "bearly-secure-session-revocation-")
	if err != nil {
		return checkResult{}, fmt.Errorf("create temporary directory: %w", err)
	}
	defer os.RemoveAll(temporaryDirectory)

	databaseConnection, err := database.Open(ctx, filepath.Join(temporaryDirectory, "probe.sqlite"))
	if err != nil {
		return checkResult{}, err
	}
	defer databaseConnection.Close()
	if err := database.Migrate(ctx, databaseConnection); err != nil {
		return checkResult{}, err
	}
	if err := insertProbeData(ctx, databaseConnection); err != nil {
		return checkResult{}, err
	}

	accountStore := accounts.NewStore(databaseConnection)
	sessionRevoker, supported := any(accountStore).(activeSessionRevoker)
	if !supported {
		return checkResult{}, fmt.Errorf("accounts.Store does not implement RevokeAllActiveSessions(context.Context) (int, error)")
	}
	databaseTimeBefore, err := currentDatabaseTime(ctx, databaseConnection)
	if err != nil {
		return checkResult{}, err
	}
	revokedCount, err := sessionRevoker.RevokeAllActiveSessions(ctx)
	if err != nil {
		return checkResult{}, err
	}
	databaseTimeAfter, err := currentDatabaseTime(ctx, databaseConnection)
	if err != nil {
		return checkResult{}, err
	}
	repeatedRevocationCount, err := sessionRevoker.RevokeAllActiveSessions(ctx)
	if err != nil {
		return checkResult{}, err
	}
	revocationTimestampMatchesDatabaseClock, err := activeRevocationsMatchDatabaseClock(
		ctx,
		databaseConnection,
		databaseTimeBefore,
		databaseTimeAfter,
	)
	if err != nil {
		return checkResult{}, err
	}

	oldSessionActive, err := sessionIsActive(ctx, accountStore, "old-session")
	if err != nil {
		return checkResult{}, err
	}
	boundarySessionActive, err := sessionIsActive(ctx, accountStore, "boundary-session")
	if err != nil {
		return checkResult{}, err
	}
	newSessionActive, err := sessionIsActive(ctx, accountStore, "new-session")
	if err != nil {
		return checkResult{}, err
	}

	var storedRevocation string
	if err := databaseConnection.QueryRowContext(
		ctx,
		"SELECT revoked_at FROM sessions WHERE token_hash = ?",
		accounts.HashSessionToken("already-revoked-session"),
	).Scan(&storedRevocation); err != nil {
		return checkResult{}, fmt.Errorf("query existing revocation: %w", err)
	}

	return checkResult{
		Revoked:                                 revokedCount,
		OldSessionActive:                        oldSessionActive,
		BoundarySessionActive:                   boundarySessionActive,
		NewSessionActive:                        newSessionActive,
		RevocationTimestampMatchesDatabaseClock: revocationTimestampMatchesDatabaseClock,
		AlreadyRevokedSessionUnchanged:          storedRevocation == originalRevocation,
		RepeatedRevocationMadeNoChanges:         repeatedRevocationCount == 0,
	}, nil
}

func currentDatabaseTime(ctx context.Context, databaseConnection *sql.DB) (string, error) {
	var databaseTime string
	if err := databaseConnection.QueryRowContext(ctx, "SELECT CURRENT_TIMESTAMP").Scan(&databaseTime); err != nil {
		return "", fmt.Errorf("query current database time: %w", err)
	}
	return databaseTime, nil
}

func activeRevocationsMatchDatabaseClock(
	ctx context.Context,
	databaseConnection *sql.DB,
	databaseTimeBefore string,
	databaseTimeAfter string,
) (bool, error) {
	var distinctTimestampCount int
	var earliestRevocation sql.NullString
	var latestRevocation sql.NullString
	if err := databaseConnection.QueryRowContext(ctx, `
		SELECT COUNT(DISTINCT revoked_at), MIN(revoked_at), MAX(revoked_at)
		FROM sessions
		WHERE token_hash IN (?, ?, ?)
	`,
		accounts.HashSessionToken("old-session"),
		accounts.HashSessionToken("boundary-session"),
		accounts.HashSessionToken("new-session"),
	).Scan(&distinctTimestampCount, &earliestRevocation, &latestRevocation); err != nil {
		return false, fmt.Errorf("query active-session revocation timestamps: %w", err)
	}
	return distinctTimestampCount == 1 &&
		earliestRevocation.Valid && earliestRevocation.String >= databaseTimeBefore &&
		latestRevocation.Valid && latestRevocation.String <= databaseTimeAfter, nil
}

func insertProbeData(ctx context.Context, databaseConnection *sql.DB) error {
	if _, err := databaseConnection.ExecContext(ctx, `
		INSERT INTO users (id, email, display_name, role, password_hash)
		VALUES (1, 'incident@example.com', 'Incident Bear', 'customer', 'unused')
	`); err != nil {
		return fmt.Errorf("insert probe user: %w", err)
	}

	now := time.Now().UTC()
	probeSessions := []probeSession{
		{token: "old-session", createdAt: now.Add(-2 * time.Hour)},
		{token: "boundary-session", createdAt: now.Add(-time.Hour)},
		{token: "new-session", createdAt: now},
		{token: "already-revoked-session", createdAt: now.Add(-3 * time.Hour), revokedAt: new(originalRevocation)},
	}
	for _, session := range probeSessions {
		if _, err := databaseConnection.ExecContext(ctx, `
			INSERT INTO sessions (
				token_hash,
				user_id,
				csrf_token,
				expires_at,
				revoked_at,
				last_authenticated_at,
				created_at
			) VALUES (?, 1, ?, ?, ?, ?, ?)
		`,
			accounts.HashSessionToken(session.token),
			session.token+"-csrf",
			now.Add(24*time.Hour).Format(time.RFC3339Nano),
			session.revokedAt,
			session.createdAt.Format(time.RFC3339Nano),
			session.createdAt.Format(time.RFC3339Nano),
		); err != nil {
			return fmt.Errorf("insert %s: %w", session.token, err)
		}
	}
	return nil
}

func sessionIsActive(ctx context.Context, accountStore *accounts.Store, token string) (bool, error) {
	_, found, err := accountStore.CurrentSession(ctx, token)
	if err != nil {
		return false, fmt.Errorf("find %s: %w", token, err)
	}
	return found, nil
}
