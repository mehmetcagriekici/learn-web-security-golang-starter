package main

import (
	"encoding/json"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"time"

	"github.com/mehmetcagriekici/learn-web-security-golang-starter/internal/httpserver"
)

type checkResults struct {
	OptionsValidated             bool `json:"optionsValidated"`
	ExcessWorkRejected           bool `json:"excessWorkRejected"`
	CapacityRecoveredAfterReturn bool `json:"capacityRecoveredAfterReturn"`
	CapacityRecoveredAfterPanic  bool `json:"capacityRecoveredAfterPanic"`
	ApplicationMounted           bool `json:"applicationMounted"`
	HealthExcluded               bool `json:"healthExcluded"`
}

func main() {
	results := checkResults{
		OptionsValidated: panics(func() {
			exerciseLoadShedder(0, 1)
		}) && panics(func() {
			exerciseLoadShedder(1, 0)
		}),
	}
	results.ExcessWorkRejected, results.CapacityRecoveredAfterReturn = checkCapacityBehavior()
	results.CapacityRecoveredAfterPanic = checkPanicRecovery()
	results.ApplicationMounted, results.HealthExcluded = checkApplicationWiring()
	if err := json.NewEncoder(os.Stdout).Encode(results); err != nil {
		log.Fatal(err)
	}
}

func exerciseLoadShedder(maxConcurrent, retryAfterSeconds int) {
	handler := httpserver.LoadShedder(maxConcurrent, retryAfterSeconds)(http.HandlerFunc(func(responseWriter http.ResponseWriter, _ *http.Request) {
		responseWriter.WriteHeader(http.StatusNoContent)
	}))
	handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/probe", nil))
}

func checkCapacityBehavior() (bool, bool) {
	requestStarted := make(chan struct{})
	releaseRequest := make(chan struct{})
	handler := httpserver.LoadShedder(1, 3)(http.HandlerFunc(func(responseWriter http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/hold" {
			close(requestStarted)
			<-releaseRequest
		}
		responseWriter.WriteHeader(http.StatusNoContent)
	}))

	firstCompleted := make(chan struct{})
	go func() {
		handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/hold", nil))
		close(firstCompleted)
	}()
	<-requestStarted

	overCapacity := httptest.NewRecorder()
	handler.ServeHTTP(overCapacity, httptest.NewRequest(http.MethodGet, "/probe", nil))
	var responseBody map[string]string
	decodeError := json.Unmarshal(overCapacity.Body.Bytes(), &responseBody)
	excessWorkRejected := overCapacity.Code == http.StatusServiceUnavailable &&
		overCapacity.Header().Get("X-In-Flight-Limit") == "1" &&
		overCapacity.Header().Get("Retry-After") == "3" &&
		decodeError == nil && responseBody["error"] != ""

	close(releaseRequest)
	<-firstCompleted
	recovered := httptest.NewRecorder()
	handler.ServeHTTP(recovered, httptest.NewRequest(http.MethodGet, "/probe", nil))
	capacityRecovered := recovered.Code == http.StatusNoContent && recovered.Header().Get("X-In-Flight-Limit") == "1"
	return excessWorkRejected, capacityRecovered
}

func checkPanicRecovery() bool {
	handler := httpserver.LoadShedder(1, 1)(http.HandlerFunc(func(responseWriter http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/panic" {
			panic("release capacity")
		}
		responseWriter.WriteHeader(http.StatusNoContent)
	}))
	func() {
		defer func() { _ = recover() }()
		handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/panic", nil))
	}()

	recovered := httptest.NewRecorder()
	handler.ServeHTTP(recovered, httptest.NewRequest(http.MethodGet, "/probe", nil))
	return recovered.Code == http.StatusNoContent
}

func checkApplicationWiring() (bool, bool) {
	appOrigin := strings.TrimRight(os.Getenv("APP_ORIGIN"), "/")
	if appOrigin == "" {
		appOrigin = "http://localhost:3030"
	}
	client := &http.Client{Timeout: 5 * time.Second}
	dynamicResponse, dynamicError := client.Get(appOrigin + "/")
	if dynamicError != nil {
		return false, false
	}
	dynamicResponse.Body.Close()
	healthResponse, healthError := client.Get(appOrigin + "/health")
	if healthError != nil {
		return false, false
	}
	healthResponse.Body.Close()
	return dynamicResponse.StatusCode == http.StatusOK && dynamicResponse.Header.Get("X-In-Flight-Limit") == "50",
		healthResponse.StatusCode == http.StatusOK && healthResponse.Header.Get("X-In-Flight-Limit") == ""
}

func panics(run func()) (didPanic bool) {
	defer func() {
		didPanic = recover() != nil
	}()
	run()
	return false
}
