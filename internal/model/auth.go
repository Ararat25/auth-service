package model

import (
	"errors"
	"fmt"
	"time"

	"github.com/Ararat25/auth-service/internal/entity"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

type Service struct {
	tokenSalt       []byte
	accessTokenTTL  time.Duration
	refreshTokenTTL time.Duration
	Storage         *gorm.DB
}

func NewAuthService(tokenSalt []byte, accessTokenTTL time.Duration, refreshTokenTTL time.Duration, storage *gorm.DB) *Service {
	return &Service{
		tokenSalt:       tokenSalt,
		accessTokenTTL:  accessTokenTTL,
		refreshTokenTTL: refreshTokenTTL,
		Storage:         storage,
	}
}

// AuthUser генерирует refresh и access токены для пользователя после входа в систему
func (s *Service) AuthUser(userId uuid.UUID, ua, ip string) (entity.Tokens, error) {
	tokens, err := s.generateTokens(userId)
	if err != nil {
		return entity.Tokens{}, err
	}

	session := entity.Session{
		UserId:        userId,
		RefreshToken:  tokens.RefreshToken,
		AccessTokenID: tokens.AccessId,
		UA:            ua,
		IP:            ip,
		CreatedAt:     time.Now().UTC(),
	}

	if err = s.Storage.Create(&session).Error; err != nil {
		return entity.Tokens{}, err
	}

	return tokens, nil
}

// VerifyUser верифицирует пользователя по access токену
func (s *Service) VerifyUser(token string) (uuid.UUID, error) {
	claims := &entity.AccessTokenClaims{}
	parsedToken, err := jwt.ParseWithClaims(token, claims, func(token *jwt.Token) (interface{}, error) {
		_, ok := token.Method.(*jwt.SigningMethodHMAC)
		if !ok {
			return nil, fmt.Errorf("incorrect signing method")
		}
		return s.tokenSalt, nil
	})
	if err != nil || !parsedToken.Valid {
		return uuid.UUID{}, fmt.Errorf("incorrect access token: %w", err)
	}

	return claims.UserId, nil
}

// RefreshToken обновляет токены пользователя
func (s *Service) RefreshToken(refreshToken, accessTokenFromReq string) (entity.Tokens, error) {
	refClaims := &entity.RefreshTokenClaims{}
	parsedRefToken, err := jwt.ParseWithClaims(refreshToken, refClaims, s.parseJWT)
	if err != nil || !parsedRefToken.Valid {
		return entity.Tokens{}, fmt.Errorf("incorrect refresh token: %w", err)
	}

	acClaims := &entity.AccessTokenClaims{}
	_, err = jwt.ParseWithClaims(accessTokenFromReq, acClaims, s.parseJWT)
	if err != nil {
		return entity.Tokens{}, fmt.Errorf("incorrect access token: %w", err)
	}

	sessionFound := entity.Session{}
	err = s.Storage.Where(&entity.Session{UserId: refClaims.UserId, RefreshToken: refreshToken}).First(&sessionFound).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return entity.Tokens{}, fmt.Errorf("entity not found: %w", err)
	}

	if acClaims.AccessTokenID != sessionFound.AccessTokenID {
		return entity.Tokens{}, fmt.Errorf("token pair mismatch")
	}

	tokens, err := s.generateTokens(refClaims.UserId)
	if err != nil {
		return entity.Tokens{}, err
	}

	sessionFound.RefreshToken = tokens.RefreshToken
	sessionFound.AccessTokenID = tokens.AccessId

	err = s.Storage.Model(&entity.Session{}).Where(entity.Session{RefreshToken: refreshToken}).Updates(&sessionFound).Error
	if err != nil {
		return entity.Tokens{}, err
	}

	return tokens, nil
}

func (s *Service) Logout(accessToken string) error {
	claims := &entity.AccessTokenClaims{}
	token, err := jwt.ParseWithClaims(accessToken, claims, s.parseJWT)
	if err != nil || !token.Valid {
		return fmt.Errorf("invalid access token: %w", err)
	}

	err = s.Storage.Where(&entity.Session{AccessTokenID: claims.AccessTokenID}).Delete(&entity.Session{}).Error
	if err != nil {
		return fmt.Errorf("failed to delete session: %w", err)
	}

	return nil
}

func (s *Service) GetSession(refreshToken string) (entity.Session, error) {
	var session entity.Session
	err := s.Storage.Where(&entity.Session{RefreshToken: refreshToken}).First(&session).Error
	if err != nil {
		return entity.Session{}, err
	}

	return session, nil
}

func (s *Service) DeleteSession(id int) error {
	return s.Storage.Delete(&entity.Session{}, id).Error
}

// generateTokens генерирует Access и Refresh токены и сохраняет refresh токен в бд
func (s *Service) generateTokens(userId uuid.UUID) (entity.Tokens, error) {
	accessTokenID := uuid.New()
	accessToken, err := s.generateAccessToken(userId, accessTokenID)
	if err != nil {
		return entity.Tokens{}, err
	}

	refreshToken, err := s.generateRefreshToken(userId)
	if err != nil {
		return entity.Tokens{}, err
	}

	return entity.Tokens{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		AccessId:     accessTokenID,
	}, nil
}

// generateAccessToken генерирует Access токен
func (s *Service) generateAccessToken(userId, accessTokenID uuid.UUID) (string, error) {
	now := time.Now()
	claims := entity.AccessTokenClaims{
		UserId:        userId,
		AccessTokenID: accessTokenID,
		RegisteredClaims: jwt.RegisteredClaims{
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(s.accessTokenTTL)),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS512, claims)
	signedToken, err := token.SignedString(s.tokenSalt)
	if err != nil {
		return "", fmt.Errorf("token signing error: %w", err)
	}

	return signedToken, nil
}

// generateRefreshToken генерирует Refresh токен
func (s *Service) generateRefreshToken(userId uuid.UUID) (string, error) {
	now := time.Now()
	claims := entity.RefreshTokenClaims{
		UserId: userId,
		RegisteredClaims: jwt.RegisteredClaims{
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(s.refreshTokenTTL)),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS512, claims)
	signedToken, err := token.SignedString(s.tokenSalt)
	if err != nil {
		return "", fmt.Errorf("token signing error: %w", err)
	}

	return signedToken, nil
}

func (s *Service) parseJWT(token *jwt.Token) (interface{}, error) {
	_, ok := token.Method.(*jwt.SigningMethodHMAC)
	if !ok {
		return nil, fmt.Errorf("incorrect signing method")
	}

	return s.tokenSalt, nil
}

//
//// hashPassword хэширует строку
//func (s *Service) hashPassword(password string) string {
//	var passwordBytes = []byte(password)
//	var sha512Hasher = sha512.New()
//
//	passwordBytes = append(passwordBytes, s.passwordSalt...)
//	sha512Hasher.Write(passwordBytes)
//
//	var hashedPasswordBytes = sha512Hasher.Sum(nil)
//	var hashedPasswordHex = hex.EncodeToString(hashedPasswordBytes)
//
//	return hashedPasswordHex
//}
//
//// doPasswordsMatch сравнивает хеш паролей
//func (s *Service) doPasswordsMatch(hashedPassword, currPassword string) bool {
//	return hashedPassword == s.hashPassword(currPassword)
//}
