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
	"net/textproto"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"

	"github.com/mehmetcagriekici/learn-web-security-golang-starter/internal/database"
	"github.com/mehmetcagriekici/learn-web-security-golang-starter/internal/uploads"
)

var safeNamePattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\.(pdf|jpg|png|webp)$`)

type results struct {
	UnsupportedRejectedWithoutSideEffects bool `json:"unsupportedRejectedWithoutSideEffects"`
	AcceptedTypesClassified               bool `json:"acceptedTypesClassified"`
	SafeStorageNames                      bool `json:"safeStorageNames"`
	ValidUploadsStored                    bool `json:"validUploadsStored"`
	ArchiveImportsClassified              bool `json:"archiveImportsClassified"`
}

type uploadProbe struct {
	name        string
	contents    []byte
	contentType string
	extension   string
}

func main() {
	output, err := checkFileUploads(context.Background())
	if err != nil {
		log.Fatal(err)
	}
	if err := json.NewEncoder(os.Stdout).Encode(output); err != nil {
		log.Fatal(err)
	}
}

func checkFileUploads(ctx context.Context) (results, error) {
	applicationOrigin := strings.TrimRight(os.Getenv("APP_ORIGIN"), "/")
	if applicationOrigin == "" {
		applicationOrigin = "http://localhost:3030"
	}
	databasePath := os.Getenv("DATABASE_URL")
	if databasePath == "" {
		databasePath = "data/bearly-secure.sqlite"
	}
	databaseConnection, err := database.Open(ctx, databasePath)
	if err != nil {
		return results{}, err
	}
	defer databaseConnection.Close()
	httpClient, err := authenticatedClient(ctx, applicationOrigin)
	if err != nil {
		return results{}, err
	}
	suffix, err := randomSuffix()
	if err != nil {
		return results{}, err
	}

	beforeFiles, err := directoryEntries("data/uploads")
	if err != nil {
		return results{}, err
	}
	unsupportedName := "unsupported-" + suffix + ".pdf"
	unsupportedStatus, err := submitUpload(ctx, httpClient, applicationOrigin, unsupportedName, []byte("not a recognized document"))
	if err != nil {
		return results{}, err
	}
	unsupportedRows, err := countOriginalName(ctx, databaseConnection, unsupportedName)
	if err != nil {
		return results{}, err
	}
	afterFiles, err := directoryEntries("data/uploads")
	if err != nil {
		return results{}, err
	}

	probes := []uploadProbe{
		{name: "pdf-" + suffix + ".bin", contents: []byte("%PDF-1.7\nprobe"), contentType: "application/pdf", extension: ".pdf"},
		{name: "jpeg-" + suffix + ".bin", contents: []byte{0xff, 0xd8, 0xff, 0xe0, 0x00}, contentType: "image/jpeg", extension: ".jpg"},
		{name: "png-" + suffix + ".bin", contents: []byte("\x89PNG\r\n\x1a\nprobe"), contentType: "image/png", extension: ".png"},
		{name: "webp-" + suffix + ".bin", contents: []byte("RIFF\x04\x00\x00\x00WEBP"), contentType: "image/webp", extension: ".webp"},
	}
	classified := true
	safeNames := true
	stored := true
	for _, probe := range probes {
		statusCode, submitErr := submitUpload(ctx, httpClient, applicationOrigin, probe.name, probe.contents)
		if submitErr != nil {
			return results{}, submitErr
		}
		contentType, storagePath, found, queryErr := findUpload(ctx, databaseConnection, probe.name)
		if queryErr != nil {
			return results{}, queryErr
		}
		classified = classified && found && contentType == probe.contentType
		safeNames = safeNames && found && filepath.Ext(storagePath) == probe.extension && safeNamePattern.MatchString(filepath.Base(storagePath))
		_, statErr := os.Stat(storagePath)
		stored = stored && statusCode == http.StatusFound && found && statErr == nil
	}

	archiveClassified, err := checkArchiveClassification()
	if err != nil {
		return results{}, err
	}
	return results{
		UnsupportedRejectedWithoutSideEffects: unsupportedStatus == http.StatusBadRequest && unsupportedRows == 0 && equalStrings(beforeFiles, afterFiles),
		AcceptedTypesClassified:               classified,
		SafeStorageNames:                      safeNames,
		ValidUploadsStored:                    stored,
		ArchiveImportsClassified:              archiveClassified,
	}, nil
}

func authenticatedClient(ctx context.Context, applicationOrigin string) (*http.Client, error) {
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, err
	}
	httpClient := &http.Client{
		Jar: jar,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	loginRequest, err := http.NewRequestWithContext(ctx, http.MethodPost, applicationOrigin+"/login", strings.NewReader(url.Values{
		"email": {"mabel@example.com"}, "password": {"password123"}, "returnTo": {"/account/tax-exemption"},
	}.Encode()))
	if err != nil {
		return nil, err
	}
	loginRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	loginResponse, err := httpClient.Do(loginRequest)
	if err != nil {
		return nil, err
	}
	defer loginResponse.Body.Close()
	if loginResponse.StatusCode != http.StatusFound {
		return nil, fmt.Errorf("log in: status %d", loginResponse.StatusCode)
	}
	return httpClient, nil
}

func submitUpload(ctx context.Context, httpClient *http.Client, applicationOrigin, filename string, contents []byte) (int, error) {
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	header := make(textproto.MIMEHeader)
	header.Set("Content-Disposition", fmt.Sprintf(`form-data; name="document"; filename="%s"`, filename))
	header.Set("Content-Type", "application/pdf")
	part, err := writer.CreatePart(header)
	if err != nil {
		return 0, err
	}
	if _, err := part.Write(contents); err != nil {
		return 0, err
	}
	if err := writer.Close(); err != nil {
		return 0, err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, applicationOrigin+"/account/tax-exemption/files", &body)
	if err != nil {
		return 0, err
	}
	request.Header.Set("Content-Type", writer.FormDataContentType())
	response, err := httpClient.Do(request)
	if err != nil {
		return 0, err
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, response.Body)
	return response.StatusCode, nil
}

func findUpload(ctx context.Context, databaseConnection *sql.DB, originalName string) (string, string, bool, error) {
	var contentType, storagePath string
	err := databaseConnection.QueryRowContext(ctx, "SELECT content_type, storage_path FROM uploaded_files WHERE original_name = ? ORDER BY id DESC LIMIT 1", originalName).Scan(&contentType, &storagePath)
	if err == sql.ErrNoRows {
		return "", "", false, nil
	}
	return contentType, storagePath, err == nil, err
}

func countOriginalName(ctx context.Context, databaseConnection *sql.DB, originalName string) (int, error) {
	var count int
	err := databaseConnection.QueryRowContext(ctx, "SELECT COUNT(*) FROM uploaded_files WHERE original_name = ?", originalName).Scan(&count)
	return count, err
}

func directoryEntries(directory string) ([]string, error) {
	entries, err := os.ReadDir(directory)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	return names, nil
}

func equalStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func checkArchiveClassification() (bool, error) {
	root, err := os.MkdirTemp("", "bearly-secure-upload-archive-check-")
	if err != nil {
		return false, err
	}
	defer os.RemoveAll(root)
	unsupportedArchive, err := createArchive("unsupported.pdf", []byte("not a document"))
	if err != nil {
		return false, err
	}
	_, unsupportedErr := extractArchive(unsupportedArchive, filepath.Join(root, "unsupported"))
	validArchive, err := createArchive("photo.txt", []byte{0xff, 0xd8, 0xff, 0xe0, 0x00})
	if err != nil {
		return false, err
	}
	valid, validErr := extractArchive(validArchive, filepath.Join(root, "valid"))
	return unsupportedErr != nil && validErr == nil && len(valid.Documents) == 1 && valid.Documents[0].ContentType == "image/jpeg", nil
}

func extractArchive(contents []byte, directory string) (uploads.ExtractedTaxDocumentArchive, error) {
	extractor := reflect.ValueOf(uploads.ExtractTaxDocumentArchive)
	arguments := []reflect.Value{reflect.ValueOf(contents), reflect.ValueOf(directory)}
	if extractor.Type().NumIn() == 3 {
		arguments = append([]reflect.Value{reflect.Zero(extractor.Type().In(0))}, arguments...)
	}
	returned := extractor.Call(arguments)
	archive := returned[0].Interface().(uploads.ExtractedTaxDocumentArchive)
	if returned[1].IsNil() {
		return archive, nil
	}
	return archive, returned[1].Interface().(error)
}

func createArchive(name string, contents []byte) ([]byte, error) {
	var buffer bytes.Buffer
	archiveWriter := zip.NewWriter(&buffer)
	part, err := archiveWriter.Create(name)
	if err != nil {
		return nil, err
	}
	if _, err := part.Write(contents); err != nil {
		return nil, err
	}
	if err := archiveWriter.Close(); err != nil {
		return nil, err
	}
	return buffer.Bytes(), nil
}

func randomSuffix() (string, error) {
	bytes := make([]byte, 6)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}
