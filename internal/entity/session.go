package entity

import (
	"time"

	"github.com/google/uuid"
)

type Session struct {
	Id            int       `json:"id" gorm:"column:id;primaryKey"`
	UserId        uuid.UUID `json:"userId" gorm:"type:uuid;column:userId"`
	RefreshToken  string    `json:"refreshToken" gorm:"column:refreshToken"`
	AccessTokenID uuid.UUID `json:"accessTokenID" gorm:"type:uuid;column:accessTokenID"`
	UA            string    `json:"ua" gorm:"type:varchar(200);column:ua"`
	IP            string    `json:"ip" gorm:"type:varchar(15);column:ip"`
	CreatedAt     time.Time `json:"createdAt" gorm:"type:timestamptz;column:createdAt"`
}
