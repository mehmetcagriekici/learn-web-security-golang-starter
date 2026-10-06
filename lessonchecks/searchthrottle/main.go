package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/mehmetcagriekici/learn-web-security-golang-starter/internal/httpserver"
	"github.com/mehmetcagriekici/learn-web-security-golang-starter/internal/templates"
)

const searchThrottleLimit = 5

type checkResults struct {
	RotatingCallersShareThrottle    bool `json:"rotatingCallersShareThrottle"`
	ThrottleMetadataValid           bool `json:"throttleMetadataValid"`
	NormalSearchAvailableAfterReset bool `json:"normalSearchAvailableAfterReset"`
}

type responseSummary struct {
	StatusCode int
	Header     http.Header
	Body       string
}

func main() {
	results, err := checkSearchThrottle()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if err := json.NewEncoder(os.Stdout).Encode(results); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func checkSearchThrottle() (checkResults, error) {
	renderer, err := templates.Load("web/templates")
	if err != nil {
		return checkResults{}, fmt.Errorf("load templates: %w", err)
	}
	probeHandler := httpserver.SearchThrottle(renderer)(http.HandlerFunc(func(responseWriter http.ResponseWriter, _ *http.Request) {
		responseWriter.WriteHeader(http.StatusNoContent)
	}))
	probeResponses := make([]responseSummary, 0, searchThrottleLimit+1)
	for requestIndex := range searchThrottleLimit + 1 {
		sourceIP := fmt.Sprintf("192.0.2.%d", requestIndex+1)
		probeResponses = append(probeResponses, probeSearch(probeHandler, sourceIP))
	}

	appOrigin := strings.TrimRight(os.Getenv("APP_ORIGIN"), "/")
	if appOrigin == "" {
		appOrigin = "http://localhost:3030"
	}
	client := &http.Client{Timeout: 5 * time.Second}
	applicationResponses := make([]responseSummary, 0, searchThrottleLimit+1)
	for range searchThrottleLimit + 1 {
		response, requestErr := liveSearch(client, appOrigin)
		if requestErr != nil {
			return checkResults{}, requestErr
		}
		applicationResponses = append(applicationResponses, response)
	}

	rotatingCallersShareThrottle := firstRequestsHaveStatus(probeResponses, http.StatusNoContent) &&
		probeResponses[searchThrottleLimit].StatusCode == http.StatusTooManyRequests &&
		firstRequestsHaveStatus(applicationResponses, http.StatusOK) &&
		applicationResponses[searchThrottleLimit].StatusCode == http.StatusTooManyRequests

	probeLimitedResponse := probeResponses[searchThrottleLimit]
	applicationLimitedResponse := applicationResponses[searchThrottleLimit]
	throttleMetadataValid := successfulMetadataValid(probeResponses) &&
		limitedMetadataValid(probeLimitedResponse) &&
		limitedMetadataValid(applicationLimitedResponse) &&
		strings.Contains(probeLimitedResponse.Body, "Search Is Busy") &&
		strings.Contains(probeLimitedResponse.Body, "Try again shortly.")

	retryAfterSeconds, retryAfterError := strconv.Atoi(applicationLimitedResponse.Header.Get("Retry-After"))
	if retryAfterError != nil || retryAfterSeconds < 1 {
		retryAfterSeconds = 1
	}
	time.Sleep(time.Duration(retryAfterSeconds)*time.Second + 100*time.Millisecond)
	resetResponse, err := liveSearch(client, appOrigin)
	if err != nil {
		return checkResults{}, err
	}
	normalSearchAvailableAfterReset := resetResponse.StatusCode == http.StatusOK &&
		resetResponse.Header.Get("RateLimit-Limit") == strconv.Itoa(searchThrottleLimit) &&
		resetResponse.Header.Get("RateLimit-Remaining") == strconv.Itoa(searchThrottleLimit-1) &&
		strings.Contains(resetResponse.Body, "SQLi Sloth")

	return checkResults{
		RotatingCallersShareThrottle:    rotatingCallersShareThrottle,
		ThrottleMetadataValid:           throttleMetadataValid,
		NormalSearchAvailableAfterReset: normalSearchAvailableAfterReset,
	}, nil
}

func firstRequestsHaveStatus(responses []responseSummary, statusCode int) bool {
	for requestIndex := range searchThrottleLimit {
		if responses[requestIndex].StatusCode != statusCode {
			return false
		}
	}
	return true
}

func successfulMetadataValid(responses []responseSummary) bool {
	for requestIndex := range searchThrottleLimit {
		response := responses[requestIndex]
		if response.Header.Get("RateLimit-Limit") != strconv.Itoa(searchThrottleLimit) ||
			response.Header.Get("RateLimit-Remaining") != strconv.Itoa(searchThrottleLimit-requestIndex-1) {
			return false
		}
	}
	return true
}

func limitedMetadataValid(response responseSummary) bool {
	retryAfterSeconds, retryAfterError := strconv.Atoi(response.Header.Get("Retry-After"))
	resetAtUnix, resetAtError := strconv.ParseInt(response.Header.Get("RateLimit-Reset"), 10, 64)
	return response.Header.Get("RateLimit-Limit") == strconv.Itoa(searchThrottleLimit) &&
		response.Header.Get("RateLimit-Remaining") == "0" &&
		retryAfterError == nil && retryAfterSeconds == 1 &&
		resetAtError == nil && resetAtUnix >= time.Now().Unix()
}

func probeSearch(handler http.Handler, sourceIP string) responseSummary {
	request := httptest.NewRequest(http.MethodGet, "http://localhost:3030/search?q=sloth", nil)
	request.RemoteAddr = net.JoinHostPort(sourceIP, "1234")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return responseSummary{
		StatusCode: response.Code,
		Header:     response.Header().Clone(),
		Body:       response.Body.String(),
	}
}

func liveSearch(client *http.Client, appOrigin string) (responseSummary, error) {
	response, err := client.Get(appOrigin + "/search?q=sloth")
	if err != nil {
		return responseSummary{}, fmt.Errorf("request product search: %w", err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		return responseSummary{}, fmt.Errorf("read product search response: %w", err)
	}
	return responseSummary{
		StatusCode: response.StatusCode,
		Header:     response.Header.Clone(),
		Body:       string(body),
	}, nil
}
