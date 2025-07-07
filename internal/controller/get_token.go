package controller

import (
	"net"
	"net/http"

	"github.com/google/uuid"
)

// GetTokens godoc
// @Summary Получить пару токенов для пользователя
// @Description Возвращает access и refresh токены для пользователя с указанным GUID.
// @Tags auth
// @Produce json
// @Param userId query string true "User GUID" example(123e4567-e89b-12d3-a456-426614174000)
// @Success 200 {object}  entity.Tokens "Пара токенов"
// @Header 200 {string} Set-Cookie "refreshToken=eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJ1c2VySWQiOiIxMjNlNDU2Ny1lODliLTEyZDMtYTQ1Ni00MjY2MTQxNzQwMDAiLCJleHAiOjE3NTIwMTM4NzgsImlhdCI6MTc1MTkyNzQ3OH0.raF4Ggl8NhyDEkifozWJJnRgZ0W9sXPKtTWqihaL3lRcfyQgd5X--FZBRYogNnzeSFUVYjQswSgZisabiyJuvw; Path=/api; HttpOnly;"
// @Failure 400 {object} ErrorResponse "Неверный userId или отсутствует"
// @Failure 401 {object} ErrorResponse "Ошибка аутентификации"
// @Router /api/tokens [get]
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
