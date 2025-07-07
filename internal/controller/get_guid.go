package controller

import (
	"encoding/json"
	"github.com/google/uuid"
	"net/http"
)

type getGUIDReq struct {
	AccessToken string `json:"accessToken"`
}

type getGUIDRes struct {
	UserId uuid.UUID `json:"userId"`
}

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
