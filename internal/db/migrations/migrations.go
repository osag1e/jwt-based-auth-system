package migrations

import (
	"database/sql"
	"os"
)

func ApplyMigrations(db *sql.DB) error {
	migrationFiles := []string{
		"internal/db/scripts/02_create_users_table.up.sql",
		"internal/db/scripts/04_create_token_table.up.sql",
	}

	for _, file := range migrationFiles {
		migrationSQL, err := os.ReadFile(file)
		if err != nil {
			return err
		}

		_, err = db.Exec(string(migrationSQL))
		if err != nil {
			return err
		}
	}

	return nil
}
