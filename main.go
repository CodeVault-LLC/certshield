package main

import (
	"log/slog"
	"os"

	"github.com/CaliDog/certstream-go"
	"github.com/codevault-llc/certshield/constants"
	"github.com/codevault-llc/certshield/output"
	"github.com/codevault-llc/certshield/scanner"
	"github.com/codevault-llc/certshield/utils"

	"github.com/joho/godotenv"
)

func main() {
	utils.InitPrettyHandler()
	err := godotenv.Load()

	if err != nil {
		utils.Logger.Error(
			"Error loading .env file",
			slog.String("error", err.Error()),
		)
	}

	output.SetupOutput()
	rules := constants.VC.OrderRules()
	scanPage := os.Getenv("SCAN_WEBSITE") == "true"

	stream, errStream := certstream.CertStreamEventStream(false)
	for {
		select {
		case jq := <-stream:
			messageType, err := jq.String("message_type")

			if err != nil {
				utils.Logger.Error(
					"Error getting message type",
					slog.String("error", err.Error()),
				)
			}

			if messageType != "certificate_update" {
				continue
			}

			scanner.Scan(jq, rules, scanPage)

		case err := <-errStream:
			utils.Logger.Error(
				"Error from CertStream",
				slog.String("error", err.Error()),
			)
		}
	}
}
