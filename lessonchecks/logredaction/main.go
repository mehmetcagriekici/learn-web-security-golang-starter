package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/mehmetcagriekici/learn-web-security-golang-starter/internal/logging"
)

const redactedValue = "[REDACTED]"

var sensitiveValues = map[string]string{
	"sessionId":   "session-secret",
	"resetToken":  "reset-token-secret",
	"resetLink":   "/password-reset/reset-link-secret",
	"secret":      "totp-secret",
	"adminNotes":  "internal-order-notes",
	"storagePath": "/private/uploads/tax-document.pdf",
}

type result struct {
	SensitiveFieldsRedacted bool `json:"sensitiveFieldsRedacted"`
	UsefulFieldsPreserved   bool `json:"usefulFieldsPreserved"`
	RawSecretsAbsent        bool `json:"rawSecretsAbsent"`
}

func main() {
	output, err := checkRedaction()
	if err != nil {
		log.Fatal(err)
	}
	if err := json.NewEncoder(os.Stdout).Encode(output); err != nil {
		log.Fatal(err)
	}
}

func checkRedaction() (result, error) {
	directory, err := os.MkdirTemp("", "log-redaction-")
	if err != nil {
		return result{}, fmt.Errorf("create temporary directory: %w", err)
	}
	defer os.RemoveAll(directory)

	logPath := filepath.Join(directory, "bearly-secure.log")
	logger, err := logging.Open(logPath)
	if err != nil {
		return result{}, fmt.Errorf("open logger: %w", err)
	}
	fields := map[string]any{"userId": 42, "success": true}
	for name, value := range sensitiveValues {
		fields[name] = value
	}
	if err := logger.Event("log_redaction_probe", fields); err != nil {
		return result{}, fmt.Errorf("write event: %w", err)
	}
	if err := logger.Close(); err != nil {
		return result{}, fmt.Errorf("close logger: %w", err)
	}
	logBytes, err := os.ReadFile(logPath)
	if err != nil {
		return result{}, fmt.Errorf("read log: %w", err)
	}

	record := map[string]any{}
	if err := json.Unmarshal(logBytes, &record); err != nil {
		return result{}, fmt.Errorf("decode log: %w", err)
	}
	allRedacted := true
	for name := range sensitiveValues {
		allRedacted = allRedacted && record[name] == redactedValue
	}
	rawSecretsAbsent := true
	for _, value := range sensitiveValues {
		rawSecretsAbsent = rawSecretsAbsent && !bytes.Contains(logBytes, []byte(value))
	}

	return result{
		SensitiveFieldsRedacted: allRedacted,
		UsefulFieldsPreserved:   record["event"] == "log_redaction_probe" && record["userId"] == float64(42) && record["success"] == true,
		RawSecretsAbsent:        rawSecretsAbsent,
	}, nil
}
