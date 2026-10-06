package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"

	"github.com/mehmetcagriekici/learn-web-security-golang-starter/internal/httpx"
	"github.com/mehmetcagriekici/learn-web-security-golang-starter/internal/templates"
)

const (
	diagnosticMessage  = "database query failed in /private/bearly-secure/orders.sql"
	safeMessage        = "The request failed. Try again, or return to the store."
	clientErrorTitle   = "Invalid Request"
	clientErrorMessage = "The submitted form is invalid."
)

type result struct {
	JSONResponseSafe      bool `json:"jsonResponseSafe"`
	ErrorPageSafe         bool `json:"errorPageSafe"`
	DiagnosticsRetained   bool `json:"diagnosticsRetained"`
	ClientErrorsPreserved bool `json:"clientErrorsPreserved"`
}

func main() {
	output, err := checkResponses()
	if err != nil {
		log.Fatal(err)
	}
	if err := json.NewEncoder(os.Stdout).Encode(output); err != nil {
		log.Fatal(err)
	}
}

func checkResponses() (result, error) {
	renderer, err := templates.Load("web/templates")
	if err != nil {
		return result{}, fmt.Errorf("load templates: %w", err)
	}

	jsonResponse := httptest.NewRecorder()
	diagnostics, err := captureOutput(func() {
		httpx.RespondWithError(jsonResponse, http.StatusInternalServerError, diagnosticMessage)
	})
	if err != nil {
		return result{}, err
	}
	jsonBody := jsonResponse.Body.String()

	errorPage := httptest.NewRecorder()
	if err := httpx.RespondWithErrorPage(errorPage, renderer, http.StatusInternalServerError, "Unhandled Error", diagnosticMessage); err != nil {
		return result{}, fmt.Errorf("render error page: %w", err)
	}
	pageBody := errorPage.Body.String()

	clientJSONResponse := httptest.NewRecorder()
	httpx.RespondWithError(clientJSONResponse, http.StatusBadRequest, clientErrorMessage)
	clientJSONBody := clientJSONResponse.Body.String()

	clientErrorPage := httptest.NewRecorder()
	if err := httpx.RespondWithErrorPage(clientErrorPage, renderer, http.StatusBadRequest, clientErrorTitle, clientErrorMessage); err != nil {
		return result{}, fmt.Errorf("render client error page: %w", err)
	}
	clientPageBody := clientErrorPage.Body.String()

	return result{
		JSONResponseSafe: jsonResponse.Code == http.StatusInternalServerError &&
			strings.Contains(jsonBody, safeMessage) &&
			!strings.Contains(jsonBody, diagnosticMessage),
		ErrorPageSafe: errorPage.Code == http.StatusInternalServerError &&
			strings.Contains(pageBody, "Something Went Wrong") &&
			strings.Contains(pageBody, safeMessage) &&
			!strings.Contains(pageBody, diagnosticMessage),
		DiagnosticsRetained: strings.Contains(diagnostics, diagnosticMessage),
		ClientErrorsPreserved: clientJSONResponse.Code == http.StatusBadRequest &&
			strings.Contains(clientJSONBody, clientErrorMessage) &&
			!strings.Contains(clientJSONBody, safeMessage) &&
			clientErrorPage.Code == http.StatusBadRequest &&
			strings.Contains(clientPageBody, clientErrorTitle) &&
			strings.Contains(clientPageBody, clientErrorMessage) &&
			!strings.Contains(clientPageBody, safeMessage),
	}, nil
}

func captureOutput(run func()) (string, error) {
	original := os.Stdout
	reader, writer, err := os.Pipe()
	if err != nil {
		return "", fmt.Errorf("capture diagnostics: %w", err)
	}
	os.Stdout = writer
	run()
	os.Stdout = original
	if err := writer.Close(); err != nil {
		return "", fmt.Errorf("close diagnostic writer: %w", err)
	}
	output, err := io.ReadAll(reader)
	_ = reader.Close()
	if err != nil {
		return "", fmt.Errorf("read diagnostics: %w", err)
	}
	return string(output), nil
}
