package controller

import (
	"encoding/json"
	"net/http"
)

type logoutReq struct {
	AccessToken string `json:"accessToken"`
}

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

	sendSuccess(w, struct {
		Status string `json:"status"`
	}{
		Status: "ok",
	}, http.StatusOK)
}
