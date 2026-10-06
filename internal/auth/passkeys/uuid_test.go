package passkeys

import (
	"encoding/json"
	"io"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"uuid"

	"github.com/mehmetcagriekici/learn-web-security-golang-starter/internal/database"
	webauthn "github.com/go-webauthn/webauthn/webauthn"
)

func TestPasskeyResponseValidatesChallengeID(t *testing.T) {
	testCases := []struct {
		name  string
		body  string
		valid bool
	}{
		{name: "valid", body: `{"challengeId":"f47ac10b-58cc-4372-a567-0e02b2c3d479","id":"credential"}`, valid: true},
		{name: "missing", body: `{"id":"credential"}`},
		{name: "empty", body: `{"challengeId":""}`},
		{name: "wrong kind", body: `{"challengeId":123}`},
		{name: "malformed", body: `{"challengeId":"not-a-uuid"}`},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			handler := &Handler{maximumRequestBytes: 4096}
			request := httptest.NewRequest("POST", "/", strings.NewReader(testCase.body))
			challengeID, _, _, err := handler.passkeyResponse(httptest.NewRecorder(), request, false)
			if (err == nil) != testCase.valid {
				t.Fatalf("passkeyResponse error = %v, want valid = %t", err, testCase.valid)
			}
			if !testCase.valid {
				return
			}
			if challengeID != uuid.MustParse("f47ac10b-58cc-4372-a567-0e02b2c3d479") {
				t.Fatalf("unexpected challenge ID: %v", challengeID)
			}
			remainingBody, err := io.ReadAll(request.Body)
			if err != nil {
				t.Fatal(err)
			}
			var remainingFields map[string]json.RawMessage
			if err := json.Unmarshal(remainingBody, &remainingFields); err != nil {
				t.Fatal(err)
			}
			if _, exists := remainingFields["challengeId"]; exists {
				t.Fatal("challenge ID was forwarded to WebAuthn")
			}
			if string(remainingFields["id"]) != `"credential"` {
				t.Fatal("credential ID was not preserved")
			}
		})
	}
}

func TestChallengeUUIDRoundTripAndSingleUse(t *testing.T) {
	databaseConnection, err := database.Open(t.Context(), filepath.Join(t.TempDir(), "passkeys.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { databaseConnection.Close() })
	if err := database.Migrate(t.Context(), databaseConnection); err != nil {
		t.Fatal(err)
	}
	challengeStore := NewStore(databaseConnection)
	sessionDetails := webauthn.SessionData{Challenge: "webauthn-challenge", Expires: time.Now().Add(time.Minute)}
	createdChallenge, err := challengeStore.CreateChallenge(t.Context(), nil, sessionDetails)
	if err != nil {
		t.Fatal(err)
	}
	consumedChallenge, found, err := challengeStore.ConsumeChallenge(t.Context(), createdChallenge.ID)
	if err != nil || !found {
		t.Fatalf("consume challenge: found=%t, err=%v", found, err)
	}
	if consumedChallenge.ID != createdChallenge.ID || consumedChallenge.SessionData.Challenge != sessionDetails.Challenge {
		t.Fatal("challenge changed during database round trip")
	}
	if _, found, err := challengeStore.ConsumeChallenge(t.Context(), createdChallenge.ID); err != nil || found {
		t.Fatalf("challenge replay: found=%t, err=%v", found, err)
	}
}
