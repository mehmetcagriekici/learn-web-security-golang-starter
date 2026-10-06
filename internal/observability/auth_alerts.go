package observability

import (
	"sync"
	"time"
	"uuid"

	"github.com/mehmetcagriekici/learn-web-security-golang-starter/internal/logging"
)

type authAlertCounter struct {
	count   int
	resetAt time.Time
}

type AuthAlertThreshold struct {
	signal      string
	threshold   int
	window      time.Duration
	logger      *logging.Logger
	mutex       sync.Mutex
	counters    map[string]authAlertCounter
	nextSweepAt time.Time
	now         func() time.Time
}

func NewAuthAlertThreshold(signal string, threshold int, window time.Duration, logger *logging.Logger) *AuthAlertThreshold {
	now := time.Now()
	return &AuthAlertThreshold{
		signal:      signal,
		threshold:   threshold,
		window:      window,
		logger:      logger,
		counters:    make(map[string]authAlertCounter),
		nextSweepAt: now.Add(window),
		now:         time.Now,
	}
}

func (threshold *AuthAlertThreshold) Record(requestID uuid.UUID, sourceIP string, userID any) {
	now := threshold.now()
	threshold.mutex.Lock()
	if !now.Before(threshold.nextSweepAt) {
		for key, counter := range threshold.counters {
			if !now.Before(counter.resetAt) {
				delete(threshold.counters, key)
			}
		}
		threshold.nextSweepAt = now.Add(threshold.window)
	}
	counter, exists := threshold.counters[sourceIP]
	if !exists || !now.Before(counter.resetAt) {
		counter = authAlertCounter{resetAt: now.Add(threshold.window)}
	}
	counter.count++
	threshold.counters[sourceIP] = counter
	shouldAlert := counter.count == threshold.threshold
	threshold.mutex.Unlock()

	if shouldAlert {
		_ = threshold.logger.Event("security_alert", map[string]any{
			"requestId":     requestID.String(),
			"outcome":       "threshold_crossed",
			"signal":        threshold.signal,
			"severity":      "warning",
			"sourceIp":      sourceIP,
			"userId":        userID,
			"threshold":     threshold.threshold,
			"windowSeconds": int(threshold.window.Seconds()),
		})
	}
}
