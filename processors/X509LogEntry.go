package processors

import (
	"log/slog"

	"github.com/codevault-llc/certshield/config"
	"github.com/codevault-llc/certshield/output"
	"github.com/codevault-llc/certshield/scanner"
	"github.com/codevault-llc/certshield/utils"
	"github.com/jmoiron/jsonq"
)

func ProcessX509LogEntry(jq jsonq.JsonQuery, rules []config.Rule, runConfig config.RunConfig) {
	leafCert, err := jq.Interface("data", "leaf_cert")
	if err != nil {
		utils.Logger.Error("Error getting leaf certificate", slog.String("error", err.Error()))
		return
	}

	issuer, err := getIssuer(jq)
	if err != nil {
		utils.Logger.Error("Error getting issuer", slog.String("error", err.Error()))
		return
	}

	allDomains, err := jq.Array("data", "leaf_cert", "all_domains")
	if err != nil {
		utils.Logger.Error("Error getting all domains", slog.String("error", err.Error()))
		return
	}

	for _, domain := range allDomains {
		domainStr, ok := domain.(string)
		if !ok {
			utils.Logger.Error("Error converting domain to string")
			continue
		}
		if !shouldProcessDomain(domainStr, runConfig) {
			continue
		}

		logMessage, err := createLogMessage(jq, leafCert, issuer, domainStr)
		if err != nil {
			utils.Logger.Error("Error creating log message", slog.String("error", err.Error()))
			continue
		}

		applyScoringRules(&logMessage, jq, rules)

		if logMessage.Score > runConfig.VendorScore {
			logMessage.Entropy = utils.CalculateEntropy(logMessage.Score)
			logMessage.ValidationMethod = scanner.GetCertValidationType(leafCert.(map[string]interface{})["extensions"].(map[string]interface{})["certificatePolicies"].(string))
			output.SendToOutput(logMessage)
		}
	}
}
