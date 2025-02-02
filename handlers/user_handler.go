package handlers

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/OsagieDG/jwt-based-auth-system/internal/models"
	"github.com/OsagieDG/jwt-based-auth-system/internal/query"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

type UserHandler struct {
	DB             *sql.DB
	userRepository query.UserRespository
}

func NewUserHandler(userRepository query.UserRespository) *UserHandler {
	return &UserHandler{
		userRepository: userRepository,
	}
}

func (h *UserHandler) HandleCreateUser(w http.ResponseWriter, r *http.Request) {
	var params models.CreateUserParams
	if err := json.NewDecoder(r.Body).Decode(&params); err != nil {
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}
	if errors := params.Validate(); len(errors) > 0 {
		writeJSONResponse(w, http.StatusBadRequest, map[string]string{
			"error": "invalid parameters",
		})
		return
	}

	user, err := models.NewUserFromParams(params)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	_, err = h.userRepository.InsertUser(context.Background(), user)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	writeJSONResponse(w, http.StatusCreated, map[string]string{"message": "User created successfully"})
}

func (h *UserHandler) HandleUserUpdate(w http.ResponseWriter, r *http.Request) {
	var (
		param     models.UpdateUserParams
		userIDStr = chi.URLParam(r, "userID")
	)

	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}

	if err := json.NewDecoder(r.Body).Decode(&param); err != nil {
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}

	_, err = h.userRepository.UpdateUserByID(context.Background(), userID, param)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	writeJSONResponse(w, http.StatusOK, map[string]string{"message": "User details has been updated"})
}

func (h *UserHandler) HandleDeleteUser(w http.ResponseWriter, r *http.Request) {
	userIDStr := chi.URLParam(r, "userID")

	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}

	err = h.userRepository.DeleteUserByID(context.Background(), userID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	writeJSONResponse(w, http.StatusOK, map[string]string{"message": "User deleted successfully"})
}

func (h *UserHandler) HandleFetchUserByID(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "userID")

	id, err := uuid.Parse(idStr)
	if err != nil {
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}

	user, err := h.userRepository.GetUserByID(context.Background(), id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			writeJSONResponse(w, http.StatusNotFound, map[string]string{
				"error": "not found",
			})
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	writeJSONResponse(w, http.StatusOK, map[string]interface{}{"data": user})
}

func (h *UserHandler) HandleFetchUsers(w http.ResponseWriter, r *http.Request) {
	users, err := h.userRepository.GetUsers(context.Background())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSONResponse(w, http.StatusOK, map[string]interface{}{"data": users})
}
