package main

import (
	"log/slog"

	"github.com/codevault-llc/certshield/config"
	"github.com/codevault-llc/certshield/core/processors"
	"github.com/codevault-llc/certshield/utils"
	"github.com/jmoiron/jsonq"
)

func Scan(jq jsonq.JsonQuery, rules []config.Rule, runConfig config.RunConfig) {
	updateType, err := jq.String("data", "update_type")
	if err != nil {
		utils.Logger.Error("Error getting update type", slog.String("error", err.Error()))
		return
	}

	switch updateType {
	case "PrecertLogEntry", "PrecertEntryWithProof":
		return
	case "X509LogEntry":
		processors.ProcessX509LogEntry(jq, rules, runConfig)
	default:
		utils.Logger.Error("Unknown update type", slog.String("update_type", updateType))
	}
}
