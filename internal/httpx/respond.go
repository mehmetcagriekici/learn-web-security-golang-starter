package httpx

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"

	"github.com/mehmetcagriekici/learn-web-security-golang-starter/internal/templates"
	"github.com/mehmetcagriekici/learn-web-security-golang-starter/internal/textutils"
)

func RespondWithError(responseWriter http.ResponseWriter, code int, message string) {
	message = textutils.StripANSI(message)
	if code >= 500 {
		fmt.Printf("Responding with error code %v, message: %v\n", code, message)
	}
	RespondWithJSON(responseWriter, code, map[string]string{"error": message})
}

func RespondWithJSON(responseWriter http.ResponseWriter, code int, payload any) {
	responseWriter.Header().Set("Content-Type", "application/json")
	responseWriter.WriteHeader(code)
	encoder := json.NewEncoder(responseWriter)
	if err := encoder.Encode(payload); err != nil {
		log.Printf("Error respondWithJSON: status code %v: %v", code, err)
	}
}

func RespondWithErrorPage(responseWriter http.ResponseWriter, renderer *templates.Renderer, statusCode int, title, message string) error {
	return renderer.Render(responseWriter, statusCode, "error", templates.ErrorPage{
		Title:      title,
		StatusCode: statusCode,
		Message:    message,
	})
}
