package main

import (
	"flag"
	"log/slog"

	"github.com/CaliDog/certstream-go"
	"github.com/codevault-llc/certshield/config"
	"github.com/codevault-llc/certshield/constants"
	"github.com/codevault-llc/certshield/core/output"
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
	constants.InitStore()

	flag.BoolVar(&config.RunConfigInstance.PingPages, "ping", false, "Ping the website")
	flag.BoolVar(&config.RunConfigInstance.Debug, "debug", false, "Debug mode")
	flag.StringVar(&config.RunConfigInstance.Filter, "filter", "", "Filter specific keywords")
	flag.IntVar(&config.RunConfigInstance.VendorScore, "vendor", 0, "Minimum vendor score")
	flag.Parse()

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

			Scan(jq, rules, config.RunConfigInstance)

		case err := <-errStream:
			utils.Logger.Error(
				"Error from CertStream",
				slog.String("error", err.Error()),
			)
		}
	}
}
