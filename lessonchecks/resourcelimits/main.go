package main

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"mime/multipart"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/mehmetcagriekici/learn-web-security-golang-starter/internal/database"
)

const (
	maximumRequestBodyBytes = 32 * 1024
	maximumUploadBytes      = 1024 * 1024
	maximumProductResults   = 50
	maximumResponseBytes    = 2 * 1024 * 1024
	probeProductCount       = 60
)

type checkResults struct {
	RequestBodiesBounded        bool `json:"requestBodiesBounded"`
	IndividualUploadBounded     bool `json:"individualUploadBounded"`
	ArchiveUploadBounded        bool `json:"archiveUploadBounded"`
	SingleFileUploadsEnforced   bool `json:"singleFileUploadsEnforced"`
	PublicProductResultsBounded bool `json:"publicProductResultsBounded"`
}

type filePart struct {
	Name     string
	Filename string
	Contents []byte
}

type responseSummary struct {
	StatusCode int
	Body       []byte
}

func main() {
	results, err := checkResourceLimits(context.Background())
	if err != nil {
		log.Fatal(err)
	}
	if err := json.NewEncoder(os.Stdout).Encode(results); err != nil {
		log.Fatal(err)
	}
}

func checkResourceLimits(ctx context.Context) (checkResults, error) {
	databasePath := os.Getenv("DATABASE_URL")
	if databasePath == "" {
		databasePath = "data/bearly-secure.sqlite"
	}
	databaseConnection, err := database.Open(ctx, databasePath)
	if err != nil {
		return checkResults{}, fmt.Errorf("open application database: %w", err)
	}
	defer databaseConnection.Close()

	probeSuffix, err := randomSuffix()
	if err != nil {
		return checkResults{}, err
	}
	if err := insertProbeProducts(ctx, databaseConnection, probeSuffix); err != nil {
		return checkResults{}, err
	}

	applicationOrigin := strings.TrimRight(os.Getenv("APP_ORIGIN"), "/")
	if applicationOrigin == "" {
		applicationOrigin = "http://localhost:3030"
	}
	requestBodiesBounded, err := checkRequestBodies(ctx, applicationOrigin, probeSuffix)
	if err != nil {
		return checkResults{}, err
	}
	individualUploadBounded, individualSingleFile, err := checkIndividualUploads(ctx, databaseConnection, applicationOrigin, probeSuffix)
	if err != nil {
		return checkResults{}, err
	}
	archiveUploadBounded, archiveSingleFile, err := checkArchiveUploads(ctx, databaseConnection, applicationOrigin, probeSuffix)
	if err != nil {
		return checkResults{}, err
	}
	publicProductResultsBounded, err := checkPublicProducts(ctx, applicationOrigin, probeSuffix)
	if err != nil {
		return checkResults{}, err
	}

	return checkResults{
		RequestBodiesBounded:        requestBodiesBounded,
		IndividualUploadBounded:     individualUploadBounded,
		ArchiveUploadBounded:        archiveUploadBounded,
		SingleFileUploadsEnforced:   individualSingleFile && archiveSingleFile,
		PublicProductResultsBounded: publicProductResultsBounded,
	}, nil
}

func checkRequestBodies(ctx context.Context, applicationOrigin, probeSuffix string) (bool, error) {
	httpClient, err := newHTTPClient()
	if err != nil {
		return false, err
	}
	smallResponse, err := submitForm(ctx, httpClient, applicationOrigin, "/login", url.Values{
		"email":    {"missing-" + probeSuffix + "@example.com"},
		"password": {"wrong-password"},
		"returnTo": {"/"},
	})
	if err != nil {
		return false, fmt.Errorf("submit ordinary form: %w", err)
	}
	largeResponse, err := submitForm(ctx, httpClient, applicationOrigin, "/login", url.Values{
		"email":    {strings.Repeat("a", maximumRequestBodyBytes+1024) + "@example.com"},
		"password": {"wrong-password"},
		"returnTo": {"/"},
	})
	if err != nil {
		return false, fmt.Errorf("submit oversized form: %w", err)
	}
	return smallResponse.StatusCode == http.StatusUnauthorized && largeResponse.StatusCode == http.StatusRequestEntityTooLarge, nil
}

func checkIndividualUploads(ctx context.Context, databaseConnection *sql.DB, applicationOrigin, probeSuffix string) (bool, bool, error) {
	httpClient, err := authenticatedClient(ctx, applicationOrigin, "mabel@example.com")
	if err != nil {
		return false, false, err
	}
	initialCount, err := countRows(ctx, databaseConnection, "uploaded_files")
	if err != nil {
		return false, false, err
	}
	validDocument := []byte("%PDF-1.7\nresource limit probe")
	validResponse, err := submitMultipart(ctx, httpClient, applicationOrigin, "/account/tax-exemption/files", []filePart{{
		Name: "document", Filename: "valid-" + probeSuffix + ".pdf", Contents: validDocument,
	}})
	if err != nil {
		return false, false, err
	}
	validCount, err := countRows(ctx, databaseConnection, "uploaded_files")
	if err != nil {
		return false, false, err
	}
	oversizedDocument := append([]byte("%PDF-1.7\n"), bytes.Repeat([]byte("x"), maximumUploadBytes)...)
	oversizedResponse, err := submitMultipart(ctx, httpClient, applicationOrigin, "/account/tax-exemption/files", []filePart{{
		Name: "document", Filename: "large-" + probeSuffix + ".pdf", Contents: oversizedDocument,
	}})
	if err != nil {
		return false, false, err
	}
	oversizedCount, err := countRows(ctx, databaseConnection, "uploaded_files")
	if err != nil {
		return false, false, err
	}
	multipleResponse, err := submitMultipart(ctx, httpClient, applicationOrigin, "/account/tax-exemption/files", []filePart{
		{Name: "document", Filename: "first-" + probeSuffix + ".pdf", Contents: validDocument},
		{Name: "document", Filename: "second-" + probeSuffix + ".pdf", Contents: validDocument},
	})
	if err != nil {
		return false, false, err
	}
	multipleCount, err := countRows(ctx, databaseConnection, "uploaded_files")
	if err != nil {
		return false, false, err
	}

	bounded := validResponse.StatusCode == http.StatusFound && validCount == initialCount+1 &&
		oversizedResponse.StatusCode == http.StatusRequestEntityTooLarge && oversizedCount == validCount
	singleFile := multipleResponse.StatusCode == http.StatusBadRequest && multipleCount == oversizedCount
	return bounded, singleFile, nil
}

func checkArchiveUploads(ctx context.Context, databaseConnection *sql.DB, applicationOrigin, probeSuffix string) (bool, bool, error) {
	httpClient, err := authenticatedClient(ctx, applicationOrigin, "sancho@example.com")
	if err != nil {
		return false, false, err
	}
	initialCount, err := countRows(ctx, databaseConnection, "imported_tax_documents")
	if err != nil {
		return false, false, err
	}
	validArchive, err := createArchive("valid-"+probeSuffix+".pdf", []byte("%PDF-1.7\nresource limit archive probe"))
	if err != nil {
		return false, false, err
	}
	validResponse, err := submitMultipart(ctx, httpClient, applicationOrigin, "/support/tax-exemptions/import", []filePart{{
		Name: "archive", Filename: "valid-" + probeSuffix + ".zip", Contents: validArchive,
	}})
	if err != nil {
		return false, false, err
	}
	validCount, err := countRows(ctx, databaseConnection, "imported_tax_documents")
	if err != nil {
		return false, false, err
	}
	oversizedArchive := append(append([]byte{}, validArchive...), bytes.Repeat([]byte("x"), maximumUploadBytes)...)
	oversizedResponse, err := submitMultipart(ctx, httpClient, applicationOrigin, "/support/tax-exemptions/import", []filePart{{
		Name: "archive", Filename: "large-" + probeSuffix + ".zip", Contents: oversizedArchive,
	}})
	if err != nil {
		return false, false, err
	}
	oversizedCount, err := countRows(ctx, databaseConnection, "imported_tax_documents")
	if err != nil {
		return false, false, err
	}
	multipleResponse, err := submitMultipart(ctx, httpClient, applicationOrigin, "/support/tax-exemptions/import", []filePart{
		{Name: "archive", Filename: "first-" + probeSuffix + ".zip", Contents: validArchive},
		{Name: "archive", Filename: "second-" + probeSuffix + ".zip", Contents: validArchive},
	})
	if err != nil {
		return false, false, err
	}
	multipleCount, err := countRows(ctx, databaseConnection, "imported_tax_documents")
	if err != nil {
		return false, false, err
	}

	bounded := validResponse.StatusCode == http.StatusSeeOther && validCount == initialCount+1 &&
		oversizedResponse.StatusCode == http.StatusRequestEntityTooLarge && oversizedCount == validCount
	singleFile := multipleResponse.StatusCode == http.StatusBadRequest && multipleCount == oversizedCount
	return bounded, singleFile, nil
}

func checkPublicProducts(ctx context.Context, applicationOrigin, probeSuffix string) (bool, error) {
	httpClient := &http.Client{Timeout: 5 * time.Second}
	apiResponse, err := request(ctx, httpClient, applicationOrigin+"/api/products")
	if err != nil {
		return false, err
	}
	var apiBody struct {
		Products []json.RawMessage `json:"products"`
	}
	if err := json.Unmarshal(apiResponse.Body, &apiBody); err != nil {
		return false, fmt.Errorf("decode public products response: %w", err)
	}
	storefrontResponse, err := request(ctx, httpClient, applicationOrigin+"/")
	if err != nil {
		return false, err
	}
	searchResponse, err := request(ctx, httpClient, applicationOrigin+"/search?q="+url.QueryEscape(probeSuffix))
	if err != nil {
		return false, err
	}
	return apiResponse.StatusCode == http.StatusOK && len(apiBody.Products) == maximumProductResults &&
		storefrontResponse.StatusCode == http.StatusOK && bytes.Count(storefrontResponse.Body, []byte(`<li class="product-card">`)) == maximumProductResults &&
		searchResponse.StatusCode == http.StatusOK && bytes.Count(searchResponse.Body, []byte(`<li class="product-card">`)) == maximumProductResults, nil
}

func insertProbeProducts(ctx context.Context, databaseConnection *sql.DB, probeSuffix string) error {
	transaction, err := databaseConnection.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin product probe transaction: %w", err)
	}
	defer transaction.Rollback()
	for productIndex := range probeProductCount {
		name := fmt.Sprintf("Resource Limit %s %02d", probeSuffix, productIndex)
		if _, err := transaction.ExecContext(ctx, `
			INSERT INTO products (name, description, image_path, price_cents, cost_cents, inventory_count, is_active)
			VALUES (?, ?, '/product-photos/placeholder.png', 1000, 500, 1, 1)
		`, name, "Probe product "+probeSuffix); err != nil {
			return fmt.Errorf("insert product probe: %w", err)
		}
	}
	if err := transaction.Commit(); err != nil {
		return fmt.Errorf("commit product probe transaction: %w", err)
	}
	return nil
}

func authenticatedClient(ctx context.Context, applicationOrigin, email string) (*http.Client, error) {
	httpClient, err := newHTTPClient()
	if err != nil {
		return nil, err
	}
	response, err := submitForm(ctx, httpClient, applicationOrigin, "/login", url.Values{
		"email":    {email},
		"password": {"password123"},
		"returnTo": {"/"},
	})
	if err != nil {
		return nil, fmt.Errorf("log in %s: %w", email, err)
	}
	if response.StatusCode != http.StatusFound {
		return nil, fmt.Errorf("log in %s: status %d", email, response.StatusCode)
	}
	return httpClient, nil
}

func newHTTPClient() (*http.Client, error) {
	cookieJar, err := cookiejar.New(nil)
	if err != nil {
		return nil, fmt.Errorf("create cookie jar: %w", err)
	}
	return &http.Client{
		Jar:     cookieJar,
		Timeout: 10 * time.Second,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}, nil
}

func submitForm(ctx context.Context, httpClient *http.Client, applicationOrigin, path string, values url.Values) (responseSummary, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, applicationOrigin+path, strings.NewReader(values.Encode()))
	if err != nil {
		return responseSummary{}, err
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Origin", applicationOrigin)
	return doRequest(httpClient, request)
}

func submitMultipart(ctx context.Context, httpClient *http.Client, applicationOrigin, path string, files []filePart) (responseSummary, error) {
	var requestBody bytes.Buffer
	multipartWriter := multipart.NewWriter(&requestBody)
	for _, file := range files {
		part, err := multipartWriter.CreateFormFile(file.Name, file.Filename)
		if err != nil {
			return responseSummary{}, fmt.Errorf("create multipart file: %w", err)
		}
		if _, err := part.Write(file.Contents); err != nil {
			return responseSummary{}, fmt.Errorf("write multipart file: %w", err)
		}
	}
	if err := multipartWriter.Close(); err != nil {
		return responseSummary{}, fmt.Errorf("close multipart body: %w", err)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, applicationOrigin+path, &requestBody)
	if err != nil {
		return responseSummary{}, err
	}
	request.Header.Set("Content-Type", multipartWriter.FormDataContentType())
	request.Header.Set("Origin", applicationOrigin)
	return doRequest(httpClient, request)
}

func request(ctx context.Context, httpClient *http.Client, targetURL string) (responseSummary, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, nil)
	if err != nil {
		return responseSummary{}, err
	}
	return doRequest(httpClient, request)
}

func doRequest(httpClient *http.Client, request *http.Request) (responseSummary, error) {
	response, err := httpClient.Do(request)
	if err != nil {
		return responseSummary{}, fmt.Errorf("request %s %s: %w", request.Method, request.URL.Path, err)
	}
	defer response.Body.Close()
	responseBody, err := io.ReadAll(io.LimitReader(response.Body, maximumResponseBytes))
	if err != nil {
		return responseSummary{}, fmt.Errorf("read %s response: %w", request.URL.Path, err)
	}
	return responseSummary{StatusCode: response.StatusCode, Body: responseBody}, nil
}

func countRows(ctx context.Context, databaseConnection *sql.DB, tableName string) (int, error) {
	var rowCount int
	if err := databaseConnection.QueryRowContext(ctx, "SELECT COUNT(*) FROM "+tableName).Scan(&rowCount); err != nil {
		return 0, fmt.Errorf("count %s: %w", tableName, err)
	}
	return rowCount, nil
}

func createArchive(filename string, contents []byte) ([]byte, error) {
	var archiveBuffer bytes.Buffer
	archiveWriter := zip.NewWriter(&archiveBuffer)
	fileWriter, err := archiveWriter.Create(filename)
	if err != nil {
		return nil, fmt.Errorf("create archive file: %w", err)
	}
	if _, err := fileWriter.Write(contents); err != nil {
		return nil, fmt.Errorf("write archive file: %w", err)
	}
	if err := archiveWriter.Close(); err != nil {
		return nil, fmt.Errorf("close archive: %w", err)
	}
	return archiveBuffer.Bytes(), nil
}

func randomSuffix() (string, error) {
	randomBytes := make([]byte, 8)
	if _, err := rand.Read(randomBytes); err != nil {
		return "", fmt.Errorf("generate probe suffix: %w", err)
	}
	return hex.EncodeToString(randomBytes), nil
}
