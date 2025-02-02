package query

import (
	"context"
	"database/sql"

	"github.com/OsagieDG/jwt-based-auth-system/internal/models"
)

type TokenRepository interface {
	SaveRefreshToken(ctx context.Context, token *models.RefreshToken) error
	GetValidRefreshToken(ctx context.Context, jti string) (*models.RefreshToken, error)
	RevokeRefreshToken(ctx context.Context, jti string) error
	DeleteRefreshToken(ctx context.Context, jti string) error
}

type TokenSQLRepository struct {
	DB *sql.DB
}

func NewTokenSQLRepository(db *sql.DB) TokenRepository {
	return &TokenSQLRepository{DB: db}
}

func (r *TokenSQLRepository) SaveRefreshToken(ctx context.Context, token *models.RefreshToken) error {
	_, _ = r.DB.ExecContext(ctx, `DELETE FROM auth.tokens WHERE user_id = $1`, token.UserID)

	query := `INSERT INTO auth.tokens (id, user_id, jti, expires_at, revoked) VALUES ($1, $2, $3, $4, $5)`
	_, err := r.DB.ExecContext(ctx, query, token.ID, token.UserID, token.JTI, token.ExpiresAt, token.Revoked)
	return err
}

func (r *TokenSQLRepository) GetValidRefreshToken(ctx context.Context, jti string) (*models.RefreshToken, error) {
	var token models.RefreshToken
	query := `SELECT id, user_id, jti, expires_at, revoked
	          FROM auth.tokens
	          WHERE jti = $1 AND revoked = false AND expires_at > NOW()`

	err := r.DB.QueryRowContext(ctx, query, jti).Scan(&token.ID, &token.UserID, &token.JTI, &token.ExpiresAt, &token.Revoked)
	if err != nil {
		return nil, err
	}
	return &token, nil
}

func (r *TokenSQLRepository) RevokeRefreshToken(ctx context.Context, jti string) error {
	query := `UPDATE auth.tokens SET revoked = true WHERE jti = $1`
	_, err := r.DB.ExecContext(ctx, query, jti)
	return err
}

func (r *TokenSQLRepository) DeleteRefreshToken(ctx context.Context, jti string) error {
	query := `DELETE FROM auth.tokens WHERE jti = $1`
	_, err := r.DB.ExecContext(ctx, query, jti)
	return err
}
