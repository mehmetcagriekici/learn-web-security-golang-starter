package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/mehmetcagriekici/learn-web-security-golang-starter/internal/database"
	"github.com/mehmetcagriekici/learn-web-security-golang-starter/internal/httpserver"
)

const (
	fulfillmentDelay    = 750 * time.Millisecond
	maximumResponseSize = 64 * 1024
	startupTimeout      = 20 * time.Second
)

type checkResults struct {
	ServerTimeoutsConfigured bool `json:"serverTimeoutsConfigured"`
	TimeoutResponseRetryable bool `json:"timeoutResponseRetryable"`
	CheckoutStatePreserved   bool `json:"checkoutStatePreserved"`
}

type checkoutProbe struct {
	StatusCode    int
	RetryAfter    string
	Body          string
	Elapsed       time.Duration
	OrdersBefore  int
	OrdersAfter   int
	CartItemCount int
}

func main() {
	results, err := checkTimeouts(context.Background())
	if err != nil {
		log.Fatal(err)
	}
	if err := json.NewEncoder(os.Stdout).Encode(results); err != nil {
		log.Fatal(err)
	}
}

func checkTimeouts(ctx context.Context) (checkResults, error) {
	probe, err := runCheckoutProbe(ctx)
	if err != nil {
		return checkResults{}, err
	}
	return checkResults{
		ServerTimeoutsConfigured: serverTimeoutsConfigured(),
		TimeoutResponseRetryable: probe.StatusCode == http.StatusServiceUnavailable && probe.RetryAfter == "1" && strings.Contains(probe.Body, "Shipping is temporarily unavailable") && probe.Elapsed < fulfillmentDelay,
		CheckoutStatePreserved:   probe.OrdersBefore == probe.OrdersAfter && probe.CartItemCount == 1,
	}, nil
}

func serverTimeoutsConfigured() bool {
	server := httpserver.NewServer(":0", http.NotFoundHandler())
	return server.ReadHeaderTimeout == 10*time.Second &&
		server.ReadTimeout == 30*time.Second &&
		server.WriteTimeout == 30*time.Second &&
		server.IdleTimeout == 120*time.Second
}

func runCheckoutProbe(ctx context.Context) (checkoutProbe, error) {
	workingDirectory, err := os.Getwd()
	if err != nil {
		return checkoutProbe{}, fmt.Errorf("get project root: %w", err)
	}
	temporaryDirectory, err := os.MkdirTemp("", "bearly-secure-timeouts-")
	if err != nil {
		return checkoutProbe{}, fmt.Errorf("create timeout-check directory: %w", err)
	}
	defer os.RemoveAll(temporaryDirectory)

	port, err := availablePort()
	if err != nil {
		return checkoutProbe{}, err
	}
	applicationOrigin := "http://localhost:" + strconv.Itoa(port)
	databasePath := filepath.Join(temporaryDirectory, "data", "bearly-secure.sqlite")
	environment := timeoutEnvironment(applicationOrigin, databasePath, port)
	seedBinary, serverBinary, err := buildProbeBinaries(ctx, workingDirectory, temporaryDirectory)
	if err != nil {
		return checkoutProbe{}, err
	}
	if err := prepareRuntimeDirectory(workingDirectory, temporaryDirectory); err != nil {
		return checkoutProbe{}, err
	}
	seedCommand := exec.CommandContext(ctx, seedBinary)
	seedCommand.Dir = temporaryDirectory
	seedCommand.Env = environment
	if seedOutput, err := seedCommand.CombinedOutput(); err != nil {
		return checkoutProbe{}, fmt.Errorf("seed timeout-check database: %w: %s", err, strings.TrimSpace(string(seedOutput)))
	}

	serverLog, err := os.Create(filepath.Join(temporaryDirectory, "server.log"))
	if err != nil {
		return checkoutProbe{}, fmt.Errorf("create timeout-check server log: %w", err)
	}
	defer serverLog.Close()
	serverCommand := exec.Command(serverBinary)
	serverCommand.Dir = temporaryDirectory
	serverCommand.Env = environment
	serverCommand.Stdout = serverLog
	serverCommand.Stderr = serverLog
	serverCommand.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := serverCommand.Start(); err != nil {
		return checkoutProbe{}, fmt.Errorf("start timeout-check server: %w", err)
	}
	defer stopProcessGroup(serverCommand)

	if err := waitForHealthyServer(ctx, applicationOrigin, serverCommand, serverLog); err != nil {
		return checkoutProbe{}, err
	}
	return exerciseCheckout(ctx, applicationOrigin, databasePath)
}

func buildProbeBinaries(ctx context.Context, projectRoot, outputDirectory string) (string, string, error) {
	seedBinary := filepath.Join(outputDirectory, "seed")
	serverBinary := filepath.Join(outputDirectory, "server")
	buildTargets := []struct {
		outputPath  string
		packagePath string
	}{
		{outputPath: seedBinary, packagePath: "./cmd/seed"},
		{outputPath: serverBinary, packagePath: "./cmd/server"},
	}
	for _, target := range buildTargets {
		buildCommand := exec.CommandContext(ctx, "go", "build", "-o", target.outputPath, target.packagePath)
		buildCommand.Dir = projectRoot
		if buildOutput, err := buildCommand.CombinedOutput(); err != nil {
			return "", "", fmt.Errorf("build timeout-check %s: %w: %s", filepath.Base(target.outputPath), err, strings.TrimSpace(string(buildOutput)))
		}
	}
	return seedBinary, serverBinary, nil
}

func prepareRuntimeDirectory(projectRoot, runtimeDirectory string) error {
	dataDirectory := filepath.Join(runtimeDirectory, "data")
	if err := os.Mkdir(dataDirectory, 0o755); err != nil {
		return fmt.Errorf("create timeout-check data directory: %w", err)
	}
	links := []struct {
		targetPath string
		linkPath   string
	}{
		{targetPath: filepath.Join(projectRoot, "web"), linkPath: filepath.Join(runtimeDirectory, "web")},
		{targetPath: filepath.Join(projectRoot, "data", "fixtures"), linkPath: filepath.Join(dataDirectory, "fixtures")},
	}
	for _, link := range links {
		if err := os.Symlink(link.targetPath, link.linkPath); err != nil {
			return fmt.Errorf("link timeout-check runtime asset %s: %w", filepath.Base(link.linkPath), err)
		}
	}
	return nil
}

func availablePort() (int, error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, fmt.Errorf("reserve timeout-check port: %w", err)
	}
	defer listener.Close()
	return listener.Addr().(*net.TCPAddr).Port, nil
}

func timeoutEnvironment(applicationOrigin, databasePath string, port int) []string {
	overrides := map[string]string{
		"ACORN_FULFILLMENT_DELAY_MS":     "750",
		"APP_ORIGIN":                     applicationOrigin,
		"DATABASE_URL":                   databasePath,
		"DATA_ENCRYPTION_ACTIVE_VERSION": "v1",
		"DATA_ENCRYPTION_KEY_V1":         strings.Repeat("1", 64),
		"DOWNLOAD_SIGNING_KEY":           strings.Repeat("2", 64),
		"PAWPAL_API_KEY":                 "bs_test_pawpal_1234567890abcdef",
		"PORT":                           strconv.Itoa(port),
	}
	environment := make([]string, 0, len(os.Environ())+len(overrides))
	for _, entry := range os.Environ() {
		name, _, _ := strings.Cut(entry, "=")
		if _, overridden := overrides[name]; !overridden {
			environment = append(environment, entry)
		}
	}
	for name, value := range overrides {
		environment = append(environment, name+"="+value)
	}
	return environment
}

func waitForHealthyServer(ctx context.Context, applicationOrigin string, serverCommand *exec.Cmd, serverLog *os.File) error {
	deadline := time.Now().Add(startupTimeout)
	httpClient := &http.Client{Timeout: time.Second}
	for time.Now().Before(deadline) {
		if serverCommand.ProcessState != nil && serverCommand.ProcessState.Exited() {
			break
		}
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, applicationOrigin+"/health", nil)
		if err != nil {
			return fmt.Errorf("create health request: %w", err)
		}
		response, requestError := httpClient.Do(request)
		if requestError == nil {
			response.Body.Close()
			if response.StatusCode == http.StatusOK {
				return nil
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	if _, err := serverLog.Seek(0, io.SeekStart); err != nil {
		return fmt.Errorf("seek timeout-check server log: %w", err)
	}
	logOutput, _ := io.ReadAll(io.LimitReader(serverLog, maximumResponseSize))
	return fmt.Errorf("timeout-check server did not become healthy: %s", strings.TrimSpace(string(logOutput)))
}

func stopProcessGroup(command *exec.Cmd) {
	if command.Process == nil {
		return
	}
	_ = syscall.Kill(-command.Process.Pid, syscall.SIGTERM)
	done := make(chan struct{})
	go func() {
		_ = command.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		_ = syscall.Kill(-command.Process.Pid, syscall.SIGKILL)
		<-done
	}
}

func exerciseCheckout(ctx context.Context, applicationOrigin, databasePath string) (checkoutProbe, error) {
	cookieJar, err := cookiejar.New(nil)
	if err != nil {
		return checkoutProbe{}, fmt.Errorf("create cookie jar: %w", err)
	}
	httpClient := &http.Client{
		Jar: cookieJar,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	loginResponse, err := submitForm(ctx, httpClient, applicationOrigin, "/login", url.Values{
		"email":    {"mabel@example.com"},
		"password": {"password123"},
		"returnTo": {"/"},
	})
	if err != nil {
		return checkoutProbe{}, fmt.Errorf("log in for timeout check: %w", err)
	}
	loginResponse.Body.Close()
	if loginResponse.StatusCode != http.StatusFound {
		return checkoutProbe{}, fmt.Errorf("log in for timeout check: status %d", loginResponse.StatusCode)
	}
	storefrontBody, err := requestBody(ctx, httpClient, applicationOrigin+"/")
	if err != nil {
		return checkoutProbe{}, err
	}
	csrfToken := extractInputValue(storefrontBody, "csrfToken")
	addResponse, err := submitForm(ctx, httpClient, applicationOrigin, "/cart/items", url.Values{
		"csrfToken": {csrfToken},
		"productId": {"1"},
		"quantity":  {"1"},
	})
	if err != nil {
		return checkoutProbe{}, fmt.Errorf("add timeout-check cart item: %w", err)
	}
	addResponse.Body.Close()
	if addResponse.StatusCode != http.StatusFound {
		return checkoutProbe{}, fmt.Errorf("add timeout-check cart item: status %d", addResponse.StatusCode)
	}

	databaseConnection, err := database.Open(ctx, databasePath)
	if err != nil {
		return checkoutProbe{}, fmt.Errorf("open timeout-check database: %w", err)
	}
	defer databaseConnection.Close()
	var ordersBefore int
	if err := databaseConnection.QueryRowContext(ctx, "SELECT count(*) FROM orders WHERE user_id = 1").Scan(&ordersBefore); err != nil {
		return checkoutProbe{}, fmt.Errorf("count orders before timeout: %w", err)
	}

	checkoutValues := url.Values{
		"csrfToken":          {csrfToken},
		"shippingName":       {"Timeout Bear"},
		"shippingAddress":    {"42 Acorn Plaza"},
		"shippingCity":       {"Gravity Falls"},
		"shippingRegion":     {"OR"},
		"shippingPostalCode": {"97001"},
		"paymentToken":       {"pawpal_tok_bearly_secure_demo"},
	}
	startedAt := time.Now()
	checkoutResponse, err := submitForm(ctx, httpClient, applicationOrigin, "/checkout", checkoutValues)
	if err != nil {
		return checkoutProbe{}, fmt.Errorf("submit timeout-check checkout: %w", err)
	}
	elapsed := time.Since(startedAt)
	checkoutBody, err := readResponseBody(checkoutResponse)
	if err != nil {
		return checkoutProbe{}, fmt.Errorf("read timeout-check checkout response: %w", err)
	}
	var ordersAfter, cartItemCount int
	if err := databaseConnection.QueryRowContext(ctx, "SELECT count(*) FROM orders WHERE user_id = 1").Scan(&ordersAfter); err != nil {
		return checkoutProbe{}, fmt.Errorf("count orders after timeout: %w", err)
	}
	if err := databaseConnection.QueryRowContext(ctx, "SELECT count(*) FROM cart_items WHERE user_id = 1").Scan(&cartItemCount); err != nil {
		return checkoutProbe{}, fmt.Errorf("count cart items after timeout: %w", err)
	}
	return checkoutProbe{
		StatusCode:    checkoutResponse.StatusCode,
		RetryAfter:    checkoutResponse.Header.Get("Retry-After"),
		Body:          checkoutBody,
		Elapsed:       elapsed,
		OrdersBefore:  ordersBefore,
		OrdersAfter:   ordersAfter,
		CartItemCount: cartItemCount,
	}, nil
}

func submitForm(ctx context.Context, httpClient *http.Client, applicationOrigin, path string, values url.Values) (*http.Response, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, applicationOrigin+path, strings.NewReader(values.Encode()))
	if err != nil {
		return nil, err
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Origin", applicationOrigin)
	return httpClient.Do(request)
}

func requestBody(ctx context.Context, httpClient *http.Client, target string) (string, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return "", fmt.Errorf("create request: %w", err)
	}
	response, err := httpClient.Do(request)
	if err != nil {
		return "", fmt.Errorf("request %s: %w", target, err)
	}
	return readResponseBody(response)
}

func readResponseBody(response *http.Response) (string, error) {
	defer response.Body.Close()
	responseBytes, err := io.ReadAll(io.LimitReader(response.Body, maximumResponseSize))
	if err != nil {
		return "", err
	}
	return string(responseBytes), nil
}

func extractInputValue(body, name string) string {
	pattern := regexp.MustCompile(`name="` + regexp.QuoteMeta(name) + `"[^>]*value="([^"]*)"`)
	match := pattern.FindStringSubmatch(body)
	if len(match) != 2 {
		return ""
	}
	return match[1]
}
