package constants

import (
	"log/slog"

	"github.com/codevault-llc/certshield/core/storage"
	"github.com/codevault-llc/certshield/utils"
)

var Store storage.PostgresStore

func InitStore() {
	store, err := storage.NewPostgresStore()
	if err != nil {
		utils.Logger.Error(
			"Error creating Postgres store",
			slog.String("error", err.Error()),
		)
	}

	if store == nil {
		utils.Logger.Error("Postgres store not initialized")
		return
	}

	Store = *store

	if err := Store.Init(); err != nil {
		utils.Logger.Error(
			"Error initializing Postgres store",
			slog.String("error", err.Error()),
		)
	}

	utils.Logger.Info("Postgres store initialized")
}
