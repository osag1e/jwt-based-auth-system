package main

import (
	"log"
	"net/http"
	"os"

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/joho/godotenv"
	"github.com/osag1e/jwt-based-auth-system/internal/db/migrations"
	"github.com/osag1e/jwt-based-auth-system/internal/db/postgres"
	"github.com/osag1e/logstack/service/middleware"
)

func main() {
	if err := godotenv.Load(); err != nil {
		log.Fatal(err)
	}

	config := &postgres.Config{
		Host:     os.Getenv("DB_HOST"),
		Port:     os.Getenv("DB_PORT"),
		Password: os.Getenv("DB_PASSWORD"),
		User:     os.Getenv("DB_USER"),
		SSLMode:  os.Getenv("DB_SSLMODE"),
		DBName:   os.Getenv("DB_NAME"),
	}

	dbConn, err := postgres.NewConnection(config)
	if err != nil {
		log.Fatal("could not connect to the database:", err)
	}

	migrationsErr := migrations.ApplyMigrations(dbConn)
	if migrationsErr != nil {
		log.Fatal("could not migrate the database:", migrationsErr)
	}

	router := initializeRouter(dbConn)
	listenAddr := os.Getenv("HTTP_LISTEN_ADDRESS")

	stack := middleware.LogStack(
		middleware.LogRequest,
		middleware.LogResponse,
		middleware.RecoverPanic,
	)

	log.Printf("Server is listening on %s...", listenAddr)
	if err := http.ListenAndServe(listenAddr, stack(router)); err != nil {
		log.Fatal("HTTP server error:", err)
	}
}
