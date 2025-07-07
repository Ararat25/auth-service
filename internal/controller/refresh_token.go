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

const webhook = "https://webhook/notify"

type refreshReq struct {
	AccessToken string `json:"accessToken"`
}

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
