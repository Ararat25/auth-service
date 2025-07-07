package controller

import (
	"github.com/google/uuid"
	"net"
	"net/http"
)

func (h *Handler) GetTokens(w http.ResponseWriter, r *http.Request) {
	userIdStr := r.URL.Query().Get("userId")
	if userIdStr == "" {
		sendError(w, "missing userId", http.StatusBadRequest)
		return
	}

	userId, err := uuid.Parse(userIdStr)
	if err != nil {
		sendError(w, "invalid userId", http.StatusBadRequest)
		return
	}

	ip, _, _ := net.SplitHostPort(r.RemoteAddr)

	tokens, err := h.service.AuthUser(userId, r.UserAgent(), ip)
	if err != nil {
		sendError(w, "failed to authenticate user: "+err.Error(), http.StatusUnauthorized)
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
