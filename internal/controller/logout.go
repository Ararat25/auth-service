package controller

import (
	"encoding/json"
	"net/http"
)

// logoutReq - стуктура для запроса на девторизацию пользователя
type logoutReq struct {
	AccessToken string `json:"accessToken" example:"eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJ1c2VySWQiOiIxMjNlNDU2Ny1lODliLTEyZDMtYTQ1Ni00MjY2MTQxNzQwMDAiLCJhaWQiOiJhYzMzNDhiNy01MGQ3LTQ1NjMtYmE5NS02MzU5OWY5MWQ4NzEiLCJleHAiOjE3NTE5MTk5ODcsImlhdCI6MTc1MTkxOTM4N30.O2ZddFrqUbI33SZ3M5rHYDeJMaYzXrAgk13VP_xJIdIxgOAc-C4qtlGrSDDNqYDcvDWbSfNtJ2JmYm0vC0e8Ug"`
}

// Logout godoc
// @Summary Деавторизация пользователя
// @Description Требует access токен, деактивирует текущую сессию.
// @Tags auth
// @Accept json
// @Produce json
// @Param accessToken body logoutReq true "Access Token"
// @Success 200 {object} StatusResponse "Статус выполнения"
// @Failure 400 {object} ErrorResponse "Некорректный access токен или ошибка выхода"
// @Router /api/logout [get]
func (h *Handler) Logout(w http.ResponseWriter, r *http.Request) {
	req := logoutReq{}
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil || req.AccessToken == "" {
		sendError(w, "invalid access token", http.StatusBadRequest)
		return
	}

	_, err = h.service.VerifyUser(req.AccessToken)
	if err != nil {
		sendError(w, "cannot verify user", http.StatusBadRequest)
		return
	}

	err = h.service.Logout(req.AccessToken)
	if err != nil {
		sendError(w, "cannot logout user", http.StatusBadRequest)
		return
	}

	sendSuccess(w, StatusResponse{
		Status: "ok",
	}, http.StatusOK)
}
