package query

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/OsagieDG/jwt-based-auth-system/internal/models"
	"github.com/google/uuid"
)

type UserRespository interface {
	InsertUser(ctx context.Context, user *models.User) (*models.User, error)
	GetUserByID(ctx context.Context, userID uuid.UUID) (*models.User, error)
	GetUserByEmail(ctx context.Context, email string) (*models.User, error)
	GetUsers(ctx context.Context) ([]models.User, error)
	UpdateUserByID(ctx context.Context, userID uuid.UUID, params models.UpdateUserParams) (*models.User, error)
	DeleteUserByID(ctx context.Context, userID uuid.UUID) error
}

type UserSQLRepository struct {
	DB *sql.DB
}

func NewUserSQLRepository(db *sql.DB) UserRespository {
	return &UserSQLRepository{DB: db}
}

func (ur *UserSQLRepository) InsertUser(ctx context.Context, user *models.User) (*models.User, error) {
	userID := models.NewUUID()

	_, err := ur.DB.ExecContext(ctx, `INSERT INTO auth.users (id, username, email, encrypted_password, is_admin) VALUES ($1, $2, $3, $4, $5)`,
		userID, user.UserName, user.Email, user.EncryptedPassword, false,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to insert user into database: %w", err)
	}

	return user, nil
}

func (ur *UserSQLRepository) UpdateUserByID(ctx context.Context, userID uuid.UUID, params models.UpdateUserParams) (*models.User, error) {
	tx, err := ur.DB.Begin()
	if err != nil {
		return nil, err
	}
	defer func() {
		if p := recover(); p != nil {
			_ = tx.Rollback()
		}
	}()

	_, err = tx.ExecContext(ctx, `UPDATE auth.users SET username = $1 WHERE id = $2`,
		params.UserName, userID,
	)
	if err != nil {
		_ = tx.Rollback()
		return nil, err
	}

	if err := tx.Commit(); err != nil {
		return nil, err
	}

	return ur.GetUserByID(ctx, userID)
}

func (ur *UserSQLRepository) GetUserByEmail(ctx context.Context, email string) (*models.User, error) {
	row := ur.DB.QueryRowContext(ctx, `SELECT id, username, email, encrypted_password, is_admin FROM auth.users WHERE email = $1`, email)

	var user models.User
	err := row.Scan(&user.ID, &user.UserName, &user.Email, &user.EncryptedPassword, &user.IsAdmin)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, errors.New("user not found")
		}
		return nil, err
	}

	return &user, nil
}

func (ur *UserSQLRepository) GetUserByID(ctx context.Context, userID uuid.UUID) (*models.User, error) {
	row := ur.DB.QueryRowContext(ctx, `SELECT id, username, email, is_admin FROM auth.users WHERE id = $1`, userID)

	var user models.User
	if err := row.Scan(&user.ID, &user.UserName, &user.Email, &user.IsAdmin); err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("user with ID %s not found", userID.String())
		}
		return nil, err
	}

	return &user, nil
}

func (ur *UserSQLRepository) GetUsers(ctx context.Context) ([]models.User, error) {
	rows, err := ur.DB.QueryContext(ctx, `SELECT id, username, email, is_admin FROM auth.users`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var users []models.User
	for rows.Next() {
		var user models.User
		if err := rows.Scan(&user.ID, &user.UserName, &user.Email, &user.IsAdmin); err != nil {
			return nil, err
		}
		users = append(users, user)
	}

	return users, nil
}

func (ur *UserSQLRepository) DeleteUserByID(ctx context.Context, userID uuid.UUID) error {
	tx, err := ur.DB.Begin()
	if err != nil {
		return err
	}
	defer func() {
		if p := recover(); p != nil {
			_ = tx.Rollback()
		}
	}()

	_, err = tx.ExecContext(ctx, `DELETE FROM auth.tokens WHERE user_id = $1`, userID)
	if err != nil {
		_ = tx.Rollback()
	}

	_, err = tx.ExecContext(ctx, `DELETE FROM auth.users WHERE id = $1`, userID)
	if err != nil {
		_ = tx.Rollback()
		return err
	}

	return tx.Commit()
}
