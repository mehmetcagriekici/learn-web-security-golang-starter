package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/mehmetcagriekici/learn-web-security-golang-starter/internal/database"
)

const (
	concurrentRequestCount = 8
	dailyQuota             = 5
	maximumResponseSize    = 64 * 1024
)

type checkResults struct {
	AuthenticationPrecedesQuota bool `json:"authenticationPrecedesQuota"`
	ConcurrentQuotaBounded      bool `json:"concurrentQuotaBounded"`
	ExhaustedRequestsRejected   bool `json:"exhaustedRequestsRejected"`
	QuotaMetadataValid          bool `json:"quotaMetadataValid"`
	UsagePersistedAtLimit       bool `json:"usagePersistedAtLimit"`
}

type quotaResponseBody struct {
	Used      int64  `json:"used"`
	Limit     int64  `json:"limit"`
	Remaining int64  `json:"remaining"`
	ResetsAt  string `json:"resets_at"`
}

type warehouseResponseBody struct {
	Integration string            `json:"integration"`
	Quota       quotaResponseBody `json:"quota"`
	Error       string            `json:"error"`
	Used        int64             `json:"used"`
	Limit       int64             `json:"limit"`
	ResetsAt    string            `json:"resets_at"`
}

type warehouseResponse struct {
	StatusCode int
	Header     http.Header
	Body       warehouseResponseBody
}

func main() {
	results, err := checkUsageQuota(context.Background())
	if err != nil {
		log.Fatal(err)
	}
	if err := json.NewEncoder(os.Stdout).Encode(results); err != nil {
		log.Fatal(err)
	}
}

func checkUsageQuota(ctx context.Context) (checkResults, error) {
	databasePath := os.Getenv("DATABASE_URL")
	if databasePath == "" {
		databasePath = "data/bearly-secure.sqlite"
	}
	databaseConnection, err := database.Open(ctx, databasePath)
	if err != nil {
		return checkResults{}, fmt.Errorf("open application database: %w", err)
	}
	defer databaseConnection.Close()

	randomKeySuffix, err := randomSuffix()
	if err != nil {
		return checkResults{}, err
	}
	validRawKey := "bs_test_quota_valid_" + randomKeySuffix
	wrongScopeRawKey := "bs_test_quota_scope_" + randomKeySuffix
	validKeyID, err := insertProbeKey(ctx, databaseConnection, "Valid Quota Probe", validRawKey, "orders:read")
	if err != nil {
		return checkResults{}, err
	}
	wrongScopeKeyID, err := insertProbeKey(ctx, databaseConnection, "Wrong Scope Probe", wrongScopeRawKey, "products:write")
	if err != nil {
		return checkResults{}, err
	}

	applicationOrigin := strings.TrimRight(os.Getenv("APP_ORIGIN"), "/")
	if applicationOrigin == "" {
		applicationOrigin = "http://localhost:3030"
	}
	httpClient := &http.Client{Timeout: 5 * time.Second}
	invalidResponse, err := requestWarehouse(ctx, httpClient, applicationOrigin, "bs_test_quota_invalid_"+randomKeySuffix)
	if err != nil {
		return checkResults{}, err
	}
	wrongScopeResponse, err := requestWarehouse(ctx, httpClient, applicationOrigin, wrongScopeRawKey)
	if err != nil {
		return checkResults{}, err
	}
	var rejectedUsageCount int64
	if err := databaseConnection.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM api_key_usage WHERE api_key_id IN (?, ?)", validKeyID, wrongScopeKeyID,
	).Scan(&rejectedUsageCount); err != nil {
		return checkResults{}, fmt.Errorf("count rejected API-key usage: %w", err)
	}

	concurrentResponses, err := requestConcurrently(ctx, httpClient, applicationOrigin, validRawKey)
	if err != nil {
		return checkResults{}, err
	}
	allowedCount, rejectedCount, metadataValid, exhaustedValid := analyzeResponses(concurrentResponses)
	var persistedUsage int64
	if err := databaseConnection.QueryRowContext(ctx,
		"SELECT COALESCE(MAX(request_count), 0) FROM api_key_usage WHERE api_key_id = ?", validKeyID,
	).Scan(&persistedUsage); err != nil {
		return checkResults{}, fmt.Errorf("read persisted API-key usage: %w", err)
	}

	return checkResults{
		AuthenticationPrecedesQuota: invalidResponse.StatusCode == http.StatusUnauthorized &&
			wrongScopeResponse.StatusCode == http.StatusForbidden && rejectedUsageCount == 0,
		ConcurrentQuotaBounded:    allowedCount == dailyQuota && rejectedCount == concurrentRequestCount-dailyQuota,
		ExhaustedRequestsRejected: exhaustedValid,
		QuotaMetadataValid:        metadataValid,
		UsagePersistedAtLimit:     persistedUsage == dailyQuota,
	}, nil
}

func insertProbeKey(ctx context.Context, databaseConnection *sql.DB, name, rawKey, scope string) (int64, error) {
	digest := sha256.Sum256([]byte(rawKey))
	queryResult, err := databaseConnection.ExecContext(ctx,
		"INSERT INTO api_keys (name, key_hash, scope) VALUES (?, ?, ?)", name, hex.EncodeToString(digest[:]), scope,
	)
	if err != nil {
		return 0, fmt.Errorf("insert %s: %w", name, err)
	}
	keyID, err := queryResult.LastInsertId()
	if err != nil {
		return 0, fmt.Errorf("read %s ID: %w", name, err)
	}
	return keyID, nil
}

func requestConcurrently(ctx context.Context, httpClient *http.Client, origin, apiKey string) ([]warehouseResponse, error) {
	responses := make([]warehouseResponse, concurrentRequestCount)
	requestErrors := make([]error, concurrentRequestCount)
	ready := make(chan struct{}, concurrentRequestCount)
	start := make(chan struct{})
	var waitGroup sync.WaitGroup
	for requestIndex := range concurrentRequestCount {
		waitGroup.Go(func() {
			ready <- struct{}{}
			<-start
			responses[requestIndex], requestErrors[requestIndex] = requestWarehouse(ctx, httpClient, origin, apiKey)
		})
	}
	for range concurrentRequestCount {
		<-ready
	}
	close(start)
	waitGroup.Wait()
	for _, requestError := range requestErrors {
		if requestError != nil {
			return nil, requestError
		}
	}
	return responses, nil
}

func requestWarehouse(ctx context.Context, httpClient *http.Client, origin, apiKey string) (warehouseResponse, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, origin+"/api/integrations/warehouse/orders", nil)
	if err != nil {
		return warehouseResponse{}, fmt.Errorf("create warehouse request: %w", err)
	}
	request.Header.Set("X-API-Key", apiKey)
	response, err := httpClient.Do(request)
	if err != nil {
		return warehouseResponse{}, fmt.Errorf("request warehouse orders: %w", err)
	}
	defer response.Body.Close()
	var responseBody warehouseResponseBody
	if err := json.NewDecoder(io.LimitReader(response.Body, maximumResponseSize)).Decode(&responseBody); err != nil {
		return warehouseResponse{}, fmt.Errorf("decode warehouse response: %w", err)
	}
	return warehouseResponse{StatusCode: response.StatusCode, Header: response.Header.Clone(), Body: responseBody}, nil
}

func analyzeResponses(responses []warehouseResponse) (int, int, bool, bool) {
	allowedCount := 0
	rejectedCount := 0
	metadataValid := true
	exhaustedValid := true
	usedValues := make(map[int64]struct{}, dailyQuota)
	sharedReset := ""
	for _, response := range responses {
		limitHeader, limitError := strconv.ParseInt(response.Header.Get("X-Quota-Limit"), 10, 64)
		remainingHeader, remainingError := strconv.ParseInt(response.Header.Get("X-Quota-Remaining"), 10, 64)
		resetHeader := response.Header.Get("X-Quota-Reset")
		if limitError != nil || remainingError != nil || limitHeader != dailyQuota || !validResetTime(resetHeader) {
			metadataValid = false
		}
		if sharedReset == "" {
			sharedReset = resetHeader
		} else if resetHeader != sharedReset {
			metadataValid = false
		}

		switch response.StatusCode {
		case http.StatusOK:
			allowedCount++
			quotaBody := response.Body.Quota
			usedValues[quotaBody.Used] = struct{}{}
			if response.Body.Integration == "" || quotaBody.Limit != dailyQuota ||
				quotaBody.Remaining != dailyQuota-quotaBody.Used || remainingHeader != quotaBody.Remaining ||
				quotaBody.ResetsAt != resetHeader {
				metadataValid = false
			}
		case http.StatusTooManyRequests:
			rejectedCount++
			retryAfter, retryAfterError := strconv.ParseInt(response.Header.Get("Retry-After"), 10, 64)
			if retryAfterError != nil || retryAfter <= 0 || response.Body.Error != "Daily API-key quota exhausted" ||
				response.Body.Used != dailyQuota || response.Body.Limit != dailyQuota ||
				response.Body.ResetsAt != resetHeader || remainingHeader != 0 {
				exhaustedValid = false
			}
		default:
			metadataValid = false
			exhaustedValid = false
		}
	}
	for expectedUsed := int64(1); expectedUsed <= dailyQuota; expectedUsed++ {
		if _, found := usedValues[expectedUsed]; !found {
			metadataValid = false
		}
	}
	return allowedCount, rejectedCount, metadataValid, exhaustedValid && rejectedCount == concurrentRequestCount-dailyQuota
}

func validResetTime(resetValue string) bool {
	resetTime, err := time.Parse("2006-01-02T15:04:05.000Z", resetValue)
	if err != nil {
		return false
	}
	now := time.Now().UTC()
	expectedReset := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC).AddDate(0, 0, 1)
	return resetTime.Equal(expectedReset)
}

func randomSuffix() (string, error) {
	randomBytes := make([]byte, 8)
	if _, err := rand.Read(randomBytes); err != nil {
		return "", fmt.Errorf("generate API-key suffix: %w", err)
	}
	return hex.EncodeToString(randomBytes), nil
}
