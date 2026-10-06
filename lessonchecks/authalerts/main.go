package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"

	"github.com/mehmetcagriekici/learn-web-security-golang-starter/internal/auth/passwords"
	"github.com/mehmetcagriekici/learn-web-security-golang-starter/internal/database"
	"github.com/mehmetcagriekici/learn-web-security-golang-starter/internal/httpserver"
	"github.com/mehmetcagriekici/learn-web-security-golang-starter/internal/logging"
	"github.com/mehmetcagriekici/learn-web-security-golang-starter/internal/storage"
)

const applicationOrigin = "http://bearly-secure.test"

type checkResult struct {
	FailedLoginAlertAtThreshold   bool `json:"failedLoginAlertAtThreshold"`
	PasswordResetAlertAtThreshold bool `json:"passwordResetAlertAtThreshold"`
	SuccessfulLoginIgnored        bool `json:"successfulLoginIgnored"`
	FailedTOTPCounted             bool `json:"failedTotpCounted"`
	KnownResetCounted             bool `json:"knownResetCounted"`
	LoginAlertValid               bool `json:"loginAlert"`
	ResetAlertValid               bool `json:"resetAlert"`
}

type logEntry map[string]any

type responseObservation struct {
	StatusCode int
	RequestID  string
	Cookies    []*http.Cookie
}

func main() {
	resultOutput := os.Stdout
	os.Stdout = os.Stderr
	result, err := runIsolatedProbe(context.Background())
	os.Stdout = resultOutput
	if err != nil {
		log.Fatal(err)
	}
	if err := json.NewEncoder(os.Stdout).Encode(result); err != nil {
		log.Fatal(err)
	}
}

func runIsolatedProbe(ctx context.Context) (checkResult, error) {
	projectRoot, err := os.Getwd()
	if err != nil {
		return checkResult{}, fmt.Errorf("get project root: %w", err)
	}
	runtimeDirectory, err := os.MkdirTemp("", "bearly-secure-auth-alerts-")
	if err != nil {
		return checkResult{}, fmt.Errorf("create alert-check directory: %w", err)
	}
	defer os.RemoveAll(runtimeDirectory)

	databaseConnection, err := database.Open(ctx, filepath.Join(runtimeDirectory, "lesson-check.sqlite"))
	if err != nil {
		return checkResult{}, err
	}
	defer databaseConnection.Close()
	if err := database.Migrate(ctx, databaseConnection); err != nil {
		return checkResult{}, err
	}
	passwordHash, err := passwords.Hash("password123")
	if err != nil {
		return checkResult{}, err
	}
	if _, err := databaseConnection.ExecContext(ctx, `
		INSERT INTO users (email, display_name, role, password_hash, totp_secret)
		VALUES ('mabel@example.com', 'Mabel Pines', 'customer', ?, NULL),
		       ('wendy@example.com', 'Wendy Corduroy', 'customer', ?, ?)
	`, passwordHash, passwordHash, "KXDYU6DRQPRQXLPY236SJJXPNGHQJVUF"); err != nil {
		return checkResult{}, fmt.Errorf("seed alert-check users: %w", err)
	}

	logPath := filepath.Join(runtimeDirectory, "lesson-check.log")
	appLogger, err := logging.Open(logPath)
	if err != nil {
		return checkResult{}, err
	}
	defer appLogger.Close()
	var encryptionKey [32]byte
	encryptionKey[0] = 1
	encryptionKeyring, err := storage.NewKeyring("v1", map[string][32]byte{"v1": encryptionKey})
	if err != nil {
		return checkResult{}, err
	}
	application, err := httpserver.New(databaseConnection, appLogger, httpserver.Options{
		AppOrigin:               applicationOrigin,
		MaxPublicProductResults: 50,
		MaxRequestBodyBytes:     32 * 1024,
		MaxUploadBytes:          1024 * 1024,
		PawPalAPIKey:            "lesson-check",
		EncryptionKeyring:       encryptionKeyring,
		DataDirectory:           runtimeDirectory,
		FixtureDirectory:        filepath.Join(projectRoot, "data", "fixtures"),
		TemplateDirectory:       filepath.Join(projectRoot, "web", "templates"),
		PublicDirectory:         filepath.Join(projectRoot, "web", "public"),
	})
	if err != nil {
		return checkResult{}, err
	}
	defer application.Close()
	return checkAuthenticationAlerts(ctx, application.Handler, logPath)
}

func checkAuthenticationAlerts(ctx context.Context, applicationHandler http.Handler, logPath string) (checkResult, error) {
	logOffset, err := logSize(logPath)
	if err != nil {
		return checkResult{}, err
	}
	failedLogins := make([]responseObservation, 0, 2)
	for attempt := range 2 {
		observation, err := postForm(ctx, applicationHandler, "/login", url.Values{
			"email":    {fmt.Sprintf("failed-login-%d@example.com", attempt)},
			"password": {"incorrect-password"},
		}, nil)
		if err != nil {
			return checkResult{}, err
		}
		failedLogins = append(failedLogins, observation)
	}
	successfulLogin, err := postForm(ctx, applicationHandler, "/login", url.Values{
		"email":    {"mabel@example.com"},
		"password": {"password123"},
	}, nil)
	if err != nil {
		return checkResult{}, err
	}
	totpPasswordStep, err := postForm(ctx, applicationHandler, "/login", url.Values{
		"email":    {"wendy@example.com"},
		"password": {"password123"},
	}, nil)
	if err != nil {
		return checkResult{}, err
	}
	challengeCookie := namedCookie(totpPasswordStep.Cookies, "totp_login_challenge")
	if challengeCookie == nil {
		return checkResult{}, fmt.Errorf("TOTP password step did not set a challenge cookie")
	}
	entriesBeforeThreshold, err := appendedEntries(logPath, logOffset)
	if err != nil {
		return checkResult{}, err
	}
	failedTOTP, err := postForm(ctx, applicationHandler, "/login/totp", url.Values{
		"mfaCode": {"not-a-code"},
	}, []*http.Cookie{challengeCookie})
	if err != nil {
		return checkResult{}, err
	}

	unknownResets := make([]responseObservation, 0, 2)
	for attempt := range 2 {
		observation, err := postForm(ctx, applicationHandler, "/password-reset", url.Values{
			"email": {fmt.Sprintf("password-reset-%d@example.com", attempt)},
		}, nil)
		if err != nil {
			return checkResult{}, err
		}
		unknownResets = append(unknownResets, observation)
	}
	knownReset, err := postForm(ctx, applicationHandler, "/password-reset", url.Values{
		"email": {"mabel@example.com"},
	}, nil)
	if err != nil {
		return checkResult{}, err
	}

	entries, err := appendedEntries(logPath, logOffset)
	if err != nil {
		return checkResult{}, err
	}
	loginAlert := findAlert(entries, "failed_logins")
	resetAlert := findAlert(entries, "password_reset_requests")
	return checkResult{
		FailedLoginAlertAtThreshold:   loginAlert != nil,
		PasswordResetAlertAtThreshold: resetAlert != nil,
		SuccessfulLoginIgnored:        !containsAlert(entriesBeforeThreshold, "failed_logins"),
		FailedTOTPCounted:             allStatus(failedLogins, http.StatusUnauthorized) && successfulLogin.StatusCode == http.StatusFound && totpPasswordStep.StatusCode == http.StatusFound && failedTOTP.StatusCode == http.StatusUnauthorized && loginAlert != nil,
		KnownResetCounted:             allStatus(unknownResets, http.StatusOK) && knownReset.StatusCode == http.StatusOK && resetAlert != nil,
		LoginAlertValid:               validAlert(loginAlert, "failed_logins", 3, 5*60, failedTOTP.RequestID),
		ResetAlertValid:               validAlert(resetAlert, "password_reset_requests", 3, 10*60, knownReset.RequestID),
	}, nil
}

func postForm(ctx context.Context, applicationHandler http.Handler, endpoint string, form url.Values, cookies []*http.Cookie) (responseObservation, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, applicationOrigin+endpoint, bytes.NewBufferString(form.Encode()))
	if err != nil {
		return responseObservation{}, fmt.Errorf("create request for %s: %w", endpoint, err)
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Origin", applicationOrigin)
	request.RemoteAddr = "192.0.2.10:12345"
	for _, cookie := range cookies {
		request.AddCookie(cookie)
	}
	recorder := httptest.NewRecorder()
	applicationHandler.ServeHTTP(recorder, request)
	response := recorder.Result()
	defer response.Body.Close()
	if _, err := io.Copy(io.Discard, response.Body); err != nil {
		return responseObservation{}, fmt.Errorf("read response from %s: %w", endpoint, err)
	}
	return responseObservation{
		StatusCode: response.StatusCode,
		RequestID:  response.Header.Get("X-Request-ID"),
		Cookies:    response.Cookies(),
	}, nil
}

func namedCookie(cookies []*http.Cookie, name string) *http.Cookie {
	for _, cookie := range cookies {
		if cookie.Name == name {
			return cookie
		}
	}
	return nil
}

func logSize(logPath string) (int64, error) {
	info, err := os.Stat(logPath)
	if err != nil {
		return 0, fmt.Errorf("stat application log: %w", err)
	}
	return info.Size(), nil
}

func appendedEntries(logPath string, offset int64) ([]logEntry, error) {
	logFile, err := os.Open(logPath)
	if err != nil {
		return nil, fmt.Errorf("open application log: %w", err)
	}
	defer logFile.Close()
	if _, err := logFile.Seek(offset, 0); err != nil {
		return nil, fmt.Errorf("seek application log: %w", err)
	}

	entries := make([]logEntry, 0)
	scanner := bufio.NewScanner(logFile)
	for scanner.Scan() {
		var entry logEntry
		if err := json.Unmarshal(scanner.Bytes(), &entry); err != nil {
			return nil, fmt.Errorf("parse application log: %w", err)
		}
		entries = append(entries, entry)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read application log: %w", err)
	}
	return entries, nil
}

func findAlert(entries []logEntry, signal string) logEntry {
	for _, entry := range entries {
		if entry["event"] == "security_alert" && entry["signal"] == signal {
			return entry
		}
	}
	return nil
}

func containsAlert(entries []logEntry, signal string) bool {
	return findAlert(entries, signal) != nil
}

func validAlert(entry logEntry, signal string, threshold, windowSeconds int, requestID string) bool {
	if entry == nil || entry["signal"] != signal || entry["outcome"] != "threshold_crossed" ||
		entry["severity"] != "warning" || entry["threshold"] != float64(threshold) ||
		entry["windowSeconds"] != float64(windowSeconds) || entry["requestId"] != requestID ||
		entry["userId"] == nil {
		return false
	}
	if timestamp, ok := entry["timestamp"].(string); !ok || timestamp == "" {
		return false
	}
	if sourceIP, ok := entry["sourceIp"].(string); !ok || sourceIP == "" {
		return false
	}
	return true
}

func allStatus(observations []responseObservation, expectedStatus int) bool {
	for _, observation := range observations {
		if observation.StatusCode != expectedStatus {
			return false
		}
	}
	return true
}
