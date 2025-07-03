package model

import (
	"errors"
	"fmt"
	"github.com/Ararat25/auth-service/internal/entity"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"gorm.io/gorm"
	"time"
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
func (s *Service) AuthUser(userId uuid.UUID) (entity.Tokens, error) {
	userFound := entity.Session{}
	result := s.Storage.Where(entity.Session{UserId: userId}).First(&userFound)
	if errors.Is(result.Error, gorm.ErrRecordNotFound) {
		return entity.Tokens{}, entity.ErrNotFound
	}

	tokens, err := s.generateTokens(userId)
	if err != nil {
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
func (s *Service) RefreshToken(token string) (entity.Tokens, error) {
	claims := &entity.RefreshTokenClaims{}
	parsedToken, err := jwt.ParseWithClaims(token, claims, func(token *jwt.Token) (interface{}, error) {
		_, ok := token.Method.(*jwt.SigningMethodHMAC)
		if !ok {
			return nil, fmt.Errorf("incorrect signing method")
		}

		return s.tokenSalt, nil
	})
	if err != nil || !parsedToken.Valid {
		return entity.Tokens{}, fmt.Errorf("incorrect refresh token: %w", err)
	}

	// поиск токена в бд
	tokenFound := entity.Session{}
	result := s.Storage.Where(&entity.Session{UserId: claims.UserId, AccessTokenID: claims.AccessTokenID}).First(&tokenFound)
	if errors.Is(result.Error, gorm.ErrRecordNotFound) {
		return entity.Tokens{}, entity.ErrNotFound
	}

	// валидация прошла успешно, можем генерить новую пару
	tokens, err := s.generateTokens(claims.UserId)
	if err != nil {
		return tokens, err
	}

	return tokens, nil
}

// generateTokens генерирует Access и Refresh токены и сохраняет refresh токен в бд
func (s *Service) generateTokens(userId uuid.UUID) (entity.Tokens, error) {
	accessTokenID := uuid.New()
	accessToken, err := s.generateAccessToken(userId)
	if err != nil {
		return entity.Tokens{}, err
	}

	refreshToken, err := s.generateRefreshToken(userId, accessTokenID)
	if err != nil {
		return entity.Tokens{}, err
	}

	res := s.Storage.Model(&entity.Session{}).Where(entity.Session{UserId: userId}).Update("accessTokenID", accessTokenID)
	if res.Error != nil {
		return entity.Tokens{}, res.Error
	}

	return entity.Tokens{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	}, nil
}

// генерирует Access токен
func (s *Service) generateAccessToken(userId uuid.UUID) (string, error) {
	now := time.Now()
	claims := entity.AccessTokenClaims{
		UserId: userId,
		RegisteredClaims: jwt.RegisteredClaims{
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(s.accessTokenTTL)), // TTL - time to live
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
func (s *Service) generateRefreshToken(userId, accessTokenID uuid.UUID) (string, error) {
	now := time.Now()
	claims := entity.RefreshTokenClaims{
		UserId:        userId,
		AccessTokenID: accessTokenID,
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
