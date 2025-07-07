package controller

import (
	"encoding/json"
	"net/http"

	"github.com/google/uuid"
)

// getGUIDReq - структура для запроса на получение GUID пользователя
type getGUIDReq struct {
	AccessToken string `json:"accessToken" example:"eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJ1c2VySWQiOiIxMjNlNDU2Ny1lODliLTEyZDMtYTQ1Ni00MjY2MTQxNzQwMDAiLCJhaWQiOiJhYzMzNDhiNy01MGQ3LTQ1NjMtYmE5NS02MzU5OWY5MWQ4NzEiLCJleHAiOjE3NTE5MTk5ODcsImlhdCI6MTc1MTkxOTM4N30.O2ZddFrqUbI33SZ3M5rHYDeJMaYzXrAgk13VP_xJIdIxgOAc-C4qtlGrSDDNqYDcvDWbSfNtJ2JmYm0vC0e8Ug"`
}

// getGUIDRes - структура для ответа на запрос для получения GUID пользователя
type getGUIDRes struct {
	UserId uuid.UUID `json:"userId" example:"123e4567-e89b-12d3-a456-426614174000"`
}

// GetGUID godoc
// @Summary Получить GUID текущего пользователя
// @Description Требует access токен, возвращает GUID пользователя.
// @Tags auth
// @Accept json
// @Produce json
// @Param accessToken body getGUIDReq true "Access Token"
// @Success 200 {object} getGUIDRes "GUID пользователя"
// @Failure 400 {object} ErrorResponse "Некорректный access токен"
// @Router /api/me [get]
func (h *Handler) GetGUID(w http.ResponseWriter, r *http.Request) {
	req := getGUIDReq{}
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil || req.AccessToken == "" {
		sendError(w, "invalid access token", http.StatusBadRequest)
		return
	}

	userId, err := h.service.VerifyUser(req.AccessToken)
	if err != nil {
		sendError(w, "cannot verify user", http.StatusBadRequest)
		return
	}

	sendSuccess(w, getGUIDRes{UserId: userId}, http.StatusOK)
}
