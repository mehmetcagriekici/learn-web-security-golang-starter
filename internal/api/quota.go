package api

import (
	"net/http"
	"strconv"

	"github.com/mehmetcagriekici/learn-web-security-golang-starter/internal/httpx"
)

type QuotaResponse struct {
	Used      int64  `json:"used"`
	Limit     int64  `json:"limit"`
	Remaining int64  `json:"remaining"`
	ResetsAt  string `json:"resets_at"`
}

type quotaExhaustedResponse struct {
	Error    string `json:"error"`
	Used     int64  `json:"used"`
	Limit    int64  `json:"limit"`
	ResetsAt string `json:"resets_at"`
}

func ToQuotaResponse(quota Quota) QuotaResponse {
	return QuotaResponse{
		Used: quota.Used, Limit: quota.Limit, Remaining: quota.Remaining, ResetsAt: quota.ResetsAt,
	}
}

func SetQuotaHeaders(responseWriter http.ResponseWriter, quota Quota) {
	responseWriter.Header().Set("X-Quota-Limit", strconv.FormatInt(quota.Limit, 10))
	responseWriter.Header().Set("X-Quota-Remaining", strconv.FormatInt(quota.Remaining, 10))
	responseWriter.Header().Set("X-Quota-Reset", quota.ResetsAt)
}

func RespondWithQuotaExhausted(responseWriter http.ResponseWriter, quota Quota) {
	SetQuotaHeaders(responseWriter, quota)
	responseWriter.Header().Set("Retry-After", strconv.FormatInt(quota.RetryAfterSeconds, 10))
	httpx.RespondWithJSON(responseWriter, http.StatusTooManyRequests, quotaExhaustedResponse{
		Error: "Daily API-key quota exhausted", Used: quota.Used, Limit: quota.Limit, ResetsAt: quota.ResetsAt,
	})
}
