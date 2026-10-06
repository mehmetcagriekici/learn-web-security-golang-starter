package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"reflect"
	"strings"
	"time"
	"unsafe"

	"github.com/mehmetcagriekici/learn-web-security-golang-starter/internal/imagepreview"
)

type result struct {
	ExactHTTPSOriginAllowed  bool `json:"exactHttpsOriginAllowed"`
	UnsafeDestinationsDenied bool `json:"unsafeDestinationsDenied"`
	ProxyDisabled            bool `json:"proxyDisabled"`
	RedirectsDisabled        bool `json:"redirectsDisabled"`
	FiveSecondDeadlines      bool `json:"fiveSecondDeadlines"`
	RedirectRejectedUnread   bool `json:"redirectRejectedUnread"`
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (function roundTripperFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return function(request)
}

type countingBody struct {
	reads int
}

func (body *countingBody) Read([]byte) (int, error) {
	body.reads++
	return 0, io.EOF
}

func (*countingBody) Close() error { return nil }

func main() {
	service := imagepreview.NewService()
	clientField := reflect.ValueOf(service).Elem().FieldByName("client")
	readableClient := reflect.NewAt(clientField.Type(), unsafe.Pointer(clientField.UnsafeAddr())).Elem()
	httpClient, isHTTPClient := readableClient.Interface().(interface {
		Do(*http.Request) (*http.Response, error)
	}).(*http.Client)

	exactAllowed := allowedByValidation(service, "https://storage.googleapis.com/example.png")
	unsafeDenied := true
	for _, rawURL := range []string{
		"http://storage.googleapis.com/example.png",
		"https://user:pass@storage.googleapis.com/example.png",
		"https://storage.googleapis.com:8443/example.png",
		"https://storage.googleapis.com.attacker.test/example.png",
		"https://127.0.0.1/example.png",
	} {
		unsafeDenied = unsafeDenied && !allowedByValidation(service, rawURL)
	}

	proxyDisabled := false
	redirectsDisabled := false
	fiveSecondDeadlines := false
	redirectRejectedUnread := false
	if isHTTPClient {
		transport, validTransport := httpClient.Transport.(*http.Transport)
		proxyDisabled = validTransport && transport.Proxy == nil
		if httpClient.CheckRedirect != nil {
			redirectRequest, _ := http.NewRequest(http.MethodGet, "https://storage.googleapis.com/redirect", nil)
			redirectsDisabled = httpClient.CheckRedirect(redirectRequest, nil) == http.ErrUseLastResponse
		}
		fiveSecondDeadlines = httpClient.Timeout == 5*time.Second && validTransport && transport.ResponseHeaderTimeout == 5*time.Second && transport.TLSHandshakeTimeout == 5*time.Second

		body := &countingBody{}
		deadlineApplied := false
		httpClient.Transport = roundTripperFunc(func(request *http.Request) (*http.Response, error) {
			deadline, hasDeadline := request.Context().Deadline()
			remaining := time.Until(deadline)
			deadlineApplied = hasDeadline && remaining > 0 && remaining <= 5*time.Second
			return &http.Response{StatusCode: http.StatusFound, Header: make(http.Header), Body: body, Request: request}, nil
		})
		_, fetchError := service.Fetch(context.Background(), "https://storage.googleapis.com/redirect", 1024)
		redirectRejectedUnread = fetchError != nil && strings.Contains(fetchError.Error(), "redirect") && body.reads == 0
		fiveSecondDeadlines = fiveSecondDeadlines && deadlineApplied
	}

	writeResult(result{
		ExactHTTPSOriginAllowed:  exactAllowed,
		UnsafeDestinationsDenied: unsafeDenied,
		ProxyDisabled:            proxyDisabled,
		RedirectsDisabled:        redirectsDisabled,
		FiveSecondDeadlines:      fiveSecondDeadlines,
		RedirectRejectedUnread:   redirectRejectedUnread,
	})
}

func allowedByValidation(service *imagepreview.Service, rawURL string) bool {
	_, err := service.Fetch(context.Background(), rawURL, 0)
	return err != nil && err.Error() == "maximum image size must be positive"
}

func writeResult(output result) {
	_ = json.NewEncoder(os.Stdout).Encode(output)
}
