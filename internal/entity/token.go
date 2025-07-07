package entity

import "github.com/google/uuid"

type Tokens struct {
	AccessToken  string    `json:"accessToken"`
	RefreshToken string    `json:"-"`
	AccessId     uuid.UUID `json:"-"`
}
