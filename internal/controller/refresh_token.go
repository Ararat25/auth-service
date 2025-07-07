package controller

import (
	"bytes"
	"encoding/json"
	"log"
	"net"
	"net/http"
	"os"
	"time"
)

const webhook = "https://webhook/notify" // webhook для информирования о попытке входа со стороннего IP

// refreshReq - стуктура для запроса на обновление токенов
type refreshReq struct {
	AccessToken string `json:"accessToken" example:"eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJ1c2VySWQiOiIxMjNlNDU2Ny1lODliLTEyZDMtYTQ1Ni00MjY2MTQxNzQwMDAiLCJhaWQiOiJhYzMzNDhiNy01MGQ3LTQ1NjMtYmE5NS02MzU5OWY5MWQ4NzEiLCJleHAiOjE3NTE5MTk5ODcsImlhdCI6MTc1MTkxOTM4N30.O2ZddFrqUbI33SZ3M5rHYDeJMaYzXrAgk13VP_xJIdIxgOAc-C4qtlGrSDDNqYDcvDWbSfNtJ2JmYm0vC0e8Ug"`
}

// RefreshToken godoc
// @Summary Обновить пару токенов
// @Description Обновляет access и refresh токены при передаче пары токенов (access в теле запроса, refresh в cookie).
// Проверяет User-Agent и IP, отправляет уведомление на webhook при смене IP.
// @Tags auth
// @Accept json
// @Produce json
// @Param accessToken body refreshReq true "Access Token"
// @Success 200 {object} entity.Tokens "Новая пара токенов"
// @Failure 400 {object} ErrorResponse "Ошибки валидации или отсутствуют токены"
// @Failure 401 {object} ErrorResponse "Несовпадение User-Agent или неуспешное обновление"
// @Router /api/refresh [get]
func (h *Handler) RefreshToken(w http.ResponseWriter, r *http.Request) {
	req := refreshReq{}
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil || req.AccessToken == "" {
		sendError(w, "invalid access token", http.StatusBadRequest)
		return
	}

	cookie, err := r.Cookie("refreshToken")
	if err != nil || cookie.Value == "" {
		sendError(w, "missing refresh token", http.StatusBadRequest)
		return
	}
	refreshToken := cookie.Value

	session, err := h.service.GetSession(refreshToken)
	if err != nil {
		sendError(w, err.Error(), http.StatusBadRequest)
		return
	}

	if session.UA != r.UserAgent() {
		_ = h.service.DeleteSession(session.Id)
		sendError(w, "user-agent mismatch", http.StatusUnauthorized)
		return
	}

	ip, _, _ := net.SplitHostPort(r.RemoteAddr)
	if session.IP != ip {
		go sendWebhook(map[string]interface{}{
			"userId": session.UserId.String(),
			"ip":     ip,
			"ua":     r.UserAgent(),
			"time":   time.Now().UTC().Format(time.RFC3339),
		})
	}

	tokens, err := h.service.RefreshToken(refreshToken, req.AccessToken)
	if err != nil {
		sendError(w, "failed to refresh tokens: "+err.Error(), http.StatusUnauthorized)
		return
	}

	refreshTokenCookie := http.Cookie{
		Name:     "refreshToken",
		Value:    tokens.RefreshToken,
		HttpOnly: true,
		Path:     "/api",
	}
	http.SetCookie(w, &refreshTokenCookie)

	sendSuccess(w, tokens, http.StatusOK)
}

func sendWebhook(payload map[string]interface{}) {
	webhookURL := webhook
	if os.Getenv("WEBHOOK") != "" {
		webhookURL = os.Getenv("WEBHOOK")
	}

	body, err := json.Marshal(payload)
	if err != nil {
		log.Println("failed to marshal webhook payload:", err)
		return
	}

	req, err := http.NewRequest("POST", webhookURL, bytes.NewBuffer(body))
	if err != nil {
		log.Println("failed to create webhook request:", err)
		return
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Println("failed to send webhook:", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		log.Println("webhook returned non-2xx:", resp.Status)
	}
}
