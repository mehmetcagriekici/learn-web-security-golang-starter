package botdetection

import (
	"net/http"
	"regexp"
	"strings"

	"github.com/mehmetcagriekici/learn-web-security-golang-starter/internal/httpx"
	"github.com/mehmetcagriekici/learn-web-security-golang-starter/internal/templates"
)

var (
	automationUserAgent      = regexp.MustCompile(`(?i)\b(bot|crawler|curl|httpie|scrapy|spider|wget)\b`)
	headlessBrowserUserAgent = regexp.MustCompile(`(?i)\bHeadlessChrome\b`)
)

type blockedPage struct {
	templates.Page
	Heading string
}

func ProtectSignup(responseWriter http.ResponseWriter, request *http.Request, renderer *templates.Renderer) bool {
	honeypot, err := httpx.FormValue(request, "companyWebsite")
	if err != nil {
		if err := httpx.RespondWithErrorPage(responseWriter, renderer, http.StatusBadRequest, "Invalid Request", "The submitted form is invalid."); err != nil {
			http.Error(responseWriter, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		}
		return true
	}

	score := 0
	if strings.TrimSpace(honeypot) != "" {
		score += 5
	}
	userAgent := request.Header.Get("User-Agent")
	if userAgent == "" {
		score += 2
	} else if automationUserAgent.MatchString(userAgent) {
		score += 4
	} else if headlessBrowserUserAgent.MatchString(userAgent) {
		score += 2
	}
	if request.Header.Get("Accept-Language") == "" {
		score++
	}
	if !strings.Contains(request.Header.Get("Accept"), "text/html") {
		score++
	}

	if score >= 5 {
		responseWriter.Header().Set("Retry-After", "60")
		_ = renderer.Render(responseWriter, http.StatusTooManyRequests, "bot-blocked", blockedPage{
			Title:   "Request Could Not Be Completed",
			Heading: "Request could not be completed",
		})
		return true
	}
	if score >= 2 {
		_ = renderer.Render(responseWriter, http.StatusForbidden, "bot-blocked", blockedPage{
			Title:   "Additional Verification Required",
			Heading: "Additional verification required",
		})
		return true
	}
	return false
}
