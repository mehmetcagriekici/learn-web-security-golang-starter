package assistant

import (
	"net/http"
	"strings"

	"github.com/mehmetcagriekici/learn-web-security-golang-starter/internal/accounts"
	"github.com/mehmetcagriekici/learn-web-security-golang-starter/internal/auth/sessions"
	"github.com/mehmetcagriekici/learn-web-security-golang-starter/internal/httpx"
	"github.com/mehmetcagriekici/learn-web-security-golang-starter/internal/logging"
	"github.com/mehmetcagriekici/learn-web-security-golang-starter/internal/templates"
)

type page struct {
	templates.Page
	DisplayName string
	Answer      string
}

type Handler struct {
	accountStore *accounts.Store
	service      *Service
	renderer     *templates.Renderer
	logger       *logging.Logger
}

func NewHandler(accountStore *accounts.Store, service *Service, renderer *templates.Renderer, logger *logging.Logger) *Handler {
	return &Handler{accountStore: accountStore, service: service, renderer: renderer, logger: logger}
}

func (handler *Handler) Page(responseWriter http.ResponseWriter, request *http.Request) {
	current, ok := handler.requireAuthentication(responseWriter, request)
	if !ok {
		return
	}
	handler.render(responseWriter, request, http.StatusOK, current.User.DisplayName, "")
}

func (handler *Handler) Ask(responseWriter http.ResponseWriter, request *http.Request) {
	current, ok := handler.requireAuthentication(responseWriter, request)
	if !ok {
		return
	}
	message, err := httpx.FormValue(request, "message")
	if err != nil {
		handler.render(responseWriter, request, http.StatusBadRequest, current.User.DisplayName, "Ask a question about an order.")
		return
	}
	message = strings.TrimSpace(message)
	if message == "" {
		handler.render(responseWriter, request, http.StatusBadRequest, current.User.DisplayName, "Ask a question about an order.")
		return
	}
	answer, err := handler.service.Answer(request.Context(), current.User.ID, message)
	if err != nil {
		handler.internalError(responseWriter, request, err)
		return
	}
	handler.render(responseWriter, request, http.StatusOK, current.User.DisplayName, answer)
}

func (handler *Handler) requireAuthentication(responseWriter http.ResponseWriter, request *http.Request) (accounts.CurrentSession, bool) {
	current, found, err := sessions.RequireWithReturnTo(responseWriter, request, handler.accountStore, "/account/assistant")
	if err != nil {
		handler.internalError(responseWriter, request, err)
		return accounts.CurrentSession{}, false
	}
	return current, found
}

func (handler *Handler) render(responseWriter http.ResponseWriter, request *http.Request, statusCode int, displayName, answer string) {
	if err := handler.renderer.Render(responseWriter, statusCode, "assistant", page{
		Title: "Order Assistant", DisplayName: displayName, Answer: answer,
	}); err != nil {
		handler.internalError(responseWriter, request, err)
	}
}

func (handler *Handler) internalError(responseWriter http.ResponseWriter, request *http.Request, err error) {
	_ = handler.logger.Event("unhandled_error", map[string]any{"method": request.Method, "path": request.URL.Path, "message": err.Error()})
	if renderErr := httpx.RespondWithErrorPage(responseWriter, handler.renderer, http.StatusInternalServerError, "Unhandled Error", err.Error()); renderErr != nil {
		http.Error(responseWriter, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
	}
}
