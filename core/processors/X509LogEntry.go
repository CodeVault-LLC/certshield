package processors

import (
	"log/slog"
	"sync"

	"github.com/codevault-llc/certshield/config"
	"github.com/codevault-llc/certshield/constants"
	"github.com/codevault-llc/certshield/core/output"
	"github.com/codevault-llc/certshield/core/scanner"
	"github.com/codevault-llc/certshield/types"
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

	var wg sync.WaitGroup
	domainChan := make(chan string, len(allDomains))

	for _, domain := range allDomains {
		domainStr, ok := domain.(string)
		if !ok {
			utils.Logger.Error("Error converting domain to string")
			continue
		}

		domainChan <- domainStr
	}

	close(domainChan)

	for i := 0; i < runConfig.MaxConcurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for domainStr := range domainChan {
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

					extensions, ok := leafCert.(map[string]interface{})["extensions"]
					if ok {
						certificatePolicies, ok := extensions.(map[string]interface{})["certificatePolicies"]
						if ok {
							logMessage.ValidationMethod = scanner.GetCertValidationType(certificatePolicies.(string))
						} else {
							utils.Logger.Error("Error getting certificate policies from extensions")
						}
					} else {
						utils.Logger.Error("Error getting extensions from leaf certificate")
					}

					output.SendToOutput(logMessage)
					store := types.Scan{
						URL:        domainStr,
						LogMessage: logMessage,

						ID: 0,
					}

					err := constants.Store.CreateScan(&store)
					if err != nil {
						utils.Logger.Error("Error creating scan", slog.String("error", err.Error()))
					}
				}
			}
		}()
	}

	wg.Wait()
}
