package handlers

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/osag1e/jwt-based-auth-system/internal/models"
	"github.com/osag1e/jwt-based-auth-system/internal/query"
)

type ContextKey string

const userID ContextKey = "userID"

var (
	jwtKey          = []byte("MY_SECRET_KEY")
	refreshTokenKey = []byte("MY_REFRESH_SECRET_KEY")
)

type Claims struct {
	UserID uuid.UUID `json:"user_id"`
	JTI    string    `json:"jti"`
	jwt.RegisteredClaims
}

type LoginParams struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type SessionHandler struct {
	DB              *sql.DB
	userRepository  query.UserRespository
	tokenRepository query.TokenRepository
}

func NewSessionHandler(db *sql.DB, userRepository query.UserRespository, tokenRepository query.TokenRepository) *SessionHandler {
	return &SessionHandler{
		DB:              db,
		userRepository:  userRepository,
		tokenRepository: tokenRepository,
	}
}

func (s *SessionHandler) Login(w http.ResponseWriter, r *http.Request) {
	var params LoginParams
	if err := json.NewDecoder(r.Body).Decode(&params); err != nil {
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}

	user, err := s.userRepository.GetUserByEmail(context.Background(), params.Email)
	if err != nil || !models.IsValidPassword(user.EncryptedPassword, params.Password) {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	expirationTime := time.Now().Add(5 * time.Minute)
	refreshExpirationTime := time.Now().Add(29 * 24 * time.Hour)
	jti := uuid.New().String()
	refreshJTI := uuid.New().String()

	claims := &Claims{
		UserID: user.ID,
		JTI:    jti,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expirationTime),
		},
	}
	refreshClaims := &Claims{
		UserID: user.ID,
		JTI:    refreshJTI,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(refreshExpirationTime),
		},
	}
	token, _ := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(jwtKey)
	refreshToken, _ := jwt.NewWithClaims(jwt.SigningMethodHS256, refreshClaims).SignedString(refreshTokenKey)

	refreshTokenModel := &models.RefreshToken{
		ID:        uuid.New(),
		UserID:    user.ID,
		JTI:       refreshJTI,
		ExpiresAt: refreshExpirationTime,
		Revoked:   false,
	}

	err = s.tokenRepository.SaveRefreshToken(context.Background(), refreshTokenModel)
	if err != nil {
		http.Error(w, "Failed to save refresh token", http.StatusInternalServerError)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "token",
		Value:    token,
		Expires:  expirationTime,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	})

	http.SetCookie(w, &http.Cookie{
		Name:     "refresh_token",
		Value:    refreshToken,
		Expires:  refreshExpirationTime,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	})

	writeJSONResponse(w, http.StatusOK, map[string]string{"message": "Login successful"})
}

func (s *SessionHandler) Logout(w http.ResponseWriter, r *http.Request) {
	c, err := r.Cookie("refresh_token")
	if err == nil {
		claims, err := s.ValidateRefreshToken(c.Value)
		if err == nil {
			_ = s.tokenRepository.DeleteRefreshToken(context.Background(), claims.JTI)
		}
	}

	http.SetCookie(w, &http.Cookie{
		Name:    "token",
		Value:   "",
		Expires: time.Now().Add(-time.Hour),
	})

	http.SetCookie(w, &http.Cookie{
		Name:    "refresh_token",
		Value:   "",
		Expires: time.Now().Add(-time.Hour),
	})

	writeJSONResponse(w, http.StatusOK, map[string]string{"message": "Logged out successfully"})
}

func (s *SessionHandler) ValidateRefreshToken(refreshToken string) (*Claims, error) {
	claims := &Claims{}
	token, err := jwt.ParseWithClaims(refreshToken, claims, func(token *jwt.Token) (interface{}, error) {
		return refreshTokenKey, nil
	})

	if err != nil || !token.Valid {
		return nil, err
	}

	if claims.ExpiresAt.Time.Before(time.Now()) {
		return nil, jwt.ErrTokenExpired
	}

	return claims, nil
}

func (s *SessionHandler) ValidateSession(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie("token")
		if err != nil {
			if s.refreshJWTToken(w, r) {
				next.ServeHTTP(w, r)
			} else {
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
			}
			return
		}

		claims := &Claims{}
		tkn, err := jwt.ParseWithClaims(c.Value, claims, func(token *jwt.Token) (interface{}, error) {
			return jwtKey, nil
		})

		if err != nil || !tkn.Valid {
			if s.refreshJWTToken(w, r) {
				next.ServeHTTP(w, r)
			} else {
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
			}
			return
		}

		ctx := context.WithValue(r.Context(), userID, claims.UserID)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (s *SessionHandler) refreshJWTToken(w http.ResponseWriter, r *http.Request) bool {
	c, err := r.Cookie("refresh_token")
	if err != nil {
		http.Error(w, "Missing refresh token", http.StatusUnauthorized)
		return false
	}

	claims, err := s.ValidateRefreshToken(c.Value)
	if err != nil {
		http.Error(w, "Invalid or expired refresh token", http.StatusUnauthorized)
		return false
	}

	storedToken, err := s.tokenRepository.GetValidRefreshToken(context.Background(), claims.JTI)
	if err != nil {
		http.Error(w, "Refresh token revoked or not found", http.StatusUnauthorized)
		return false
	}

	if storedToken.Revoked {
		http.Error(w, "Refresh token revoked", http.StatusUnauthorized)
		return false
	}

	expirationTime := time.Now().Add(1 * time.Minute)
	refreshExpirationTime := time.Now().Add(2 * time.Minute)

	newJTI := uuid.New().String()
	newRefreshJTI := uuid.New().String()

	newClaims := &Claims{
		UserID: claims.UserID,
		JTI:    newJTI,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expirationTime),
		},
	}

	newRefreshClaims := &Claims{
		UserID: claims.UserID,
		JTI:    newRefreshJTI,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(refreshExpirationTime),
		},
	}

	_, err = jwt.NewWithClaims(jwt.SigningMethodHS256, newClaims).SignedString(jwtKey)
	if err != nil {
		http.Error(w, "Failed to generate new access token", http.StatusInternalServerError)
		return false
	}

	newRefreshToken, err := jwt.NewWithClaims(jwt.SigningMethodHS256, newRefreshClaims).SignedString(refreshTokenKey)
	if err != nil {
		http.Error(w, "Failed to generate new refresh token", http.StatusInternalServerError)
		return false
	}

	if err := s.tokenRepository.RevokeRefreshToken(context.Background(), claims.JTI); err != nil {
		http.Error(w, "Failed to revoke old refresh token", http.StatusInternalServerError)
		return false
	}

	newRefreshTokenModel := &models.RefreshToken{
		ID:        uuid.New(),
		UserID:    claims.UserID,
		JTI:       newRefreshJTI,
		ExpiresAt: refreshExpirationTime,
		Revoked:   false,
	}

	if err := s.tokenRepository.SaveRefreshToken(context.Background(), newRefreshTokenModel); err != nil {
		http.Error(w, "Failed to save new refresh token", http.StatusInternalServerError)
		return false
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "refresh_token",
		Value:    "",
		Expires:  time.Now().Add(-1 * time.Hour), // Expires the old token
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	})

	// Sets the new refresh token
	http.SetCookie(w, &http.Cookie{
		Name:     "refresh_token",
		Value:    newRefreshToken,
		Expires:  refreshExpirationTime,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	})

	return true
}
