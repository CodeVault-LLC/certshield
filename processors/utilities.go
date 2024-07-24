package processors

import (
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/codevault-llc/certshield/config"
	"github.com/codevault-llc/certshield/scanner"
	"github.com/codevault-llc/certshield/types"
	"github.com/codevault-llc/certshield/utils"
	"github.com/jmoiron/jsonq"
)

func getIssuer(jq jsonq.JsonQuery) (map[string]interface{}, error) {
	issuerInterface, err := jq.Interface("data", "leaf_cert", "issuer")
	if err != nil {
		return nil, err
	}
	issuer, ok := issuerInterface.(map[string]interface{})
	if !ok {
		return nil, errors.New("error parsing issuer")
	}
	return issuer, nil
}

func shouldProcessDomain(domainStr string, runConfig config.RunConfig) bool {
	if runConfig.Filter != "" && !utils.FilterDomain(domainStr, runConfig.Filter) {
		return false
	}
	if runConfig.PingPages {
		validUrl := utils.ValidateURL(domainStr)
		statusCode, err := utils.GetWebsite(validUrl)
		if err != "" || !utils.ValidateResponse(statusCode) {
			return false
		}
	}
	return true
}

func createLogMessage(jq jsonq.JsonQuery, leafCert interface{}, issuer map[string]interface{}, domainStr string) (types.LogMessage, error) {
	subjectOrg := getStringOrDefault(jq, "data", "leaf_cert", "subject", "O", "N/A")
	organizationUnit := getStringOrDefault(jq, "data", "leaf_cert", "subject", "OU", "N/A")
	subjectCommonName := getStringOrDefault(jq, "data", "leaf_cert", "subject", "CN", "N/A")

	certificate, err := json.MarshalIndent(leafCert, "", "\t")
	if err != nil {
		return types.LogMessage{}, fmt.Errorf("error marshalling certificate: %v", err)
	}

	leafCertMap := leafCert.(map[string]interface{})

	logMessage := types.LogMessage{
		Timestamp:           time.Now().UTC(),
		Domain:              domainStr,
		Vendor:              utils.GetSeverity(0),
		Score:               0,
		Matches:             []string{},
		IssuerCommonName:    issuer["CN"].(string),
		SubjectCommonName:   subjectCommonName,
		IssuerOrganization:  issuer["O"].(string),
		SubjectOrganization: subjectOrg,
		SerialNumber:        leafCertMap["serial_number"].(string),
		NotBefore:           time.Unix(int64(leafCertMap["not_before"].(float64)), 0),
		NotAfter:            time.Unix(int64(leafCertMap["not_after"].(float64)), 0),
		KeyUsage:            leafCertMap["extensions"].(map[string]interface{})["keyUsage"].(string),
		ExtendedKeyUsage:    leafCertMap["extensions"].(map[string]interface{})["extendedKeyUsage"].(string),
		SignatureAlgorithm:  leafCertMap["signature_algorithm"].(string),
		OrganizationUnit:    organizationUnit,
		Certificate:         string(certificate),
		IsExpired:           time.Now().UTC().After(time.Unix(int64(leafCertMap["not_after"].(float64)), 0)),
		IsRevoked:           false,
		IsWildcard:          domainStr[0] == '*',
		IssuanceDate:        time.Unix(int64(leafCertMap["not_before"].(float64)), 0),
		ValidationMethod:    "N/A",
		Country:             "N/A",
		IPAddress:           "N/A",
		CertSource:          "CertStream",
		Notes:               "N/A",
	}

	return logMessage, nil
}

func getStringOrDefault(jq jsonq.JsonQuery, path ...string) string {
	value, err := jq.String(path...)
	if err != nil {
		return "N/A"
	}
	return value
}

// applyScoringRules applies scoring rules to a log message
func applyScoringRules(logMessage *types.LogMessage, jq jsonq.JsonQuery, rules []config.Rule) {
	var wg sync.WaitGroup
	mu := &sync.Mutex{}

	if logMessage.IsExpired {
		mu.Lock()
		logMessage.Score += 15
		logMessage.Matches = append(logMessage.Matches, "Expired")
		mu.Unlock()
	}

	wg.Add(2)
	go func() {
		defer wg.Done()
		scannedCAScore, scannedCAMatches := scanner.ScanCA(jq)
		mu.Lock()
		logMessage.Score += scannedCAScore
		logMessage.Matches = append(logMessage.Matches, scannedCAMatches...)
		mu.Unlock()
	}()
	go func() {
		defer wg.Done()
		scannedDomainScore, scannedDomainMatches := scanner.ScanDomain(logMessage.Domain)
		mu.Lock()
		logMessage.Score += scannedDomainScore
		logMessage.Matches = append(logMessage.Matches, scannedDomainMatches...)
		mu.Unlock()
	}()
	wg.Wait()

	domainStr := logMessage.Domain
	if domainStr[0] == '*' {
		domainStr = domainStr[2:]
	}

	// Create a channel to handle scoring rule results
	ruleResults := make(chan ruleResult, len(rules))

	for _, rule := range rules {
		for _, word := range rule.Words {
			wg.Add(1)
			go func(rule config.Rule, word string, domainStr string) {
				defer wg.Done()
				if len(scanner.GenericScan(rule, domainStr)) > 0 {
					ruleResults <- ruleResult{
						score: 1,
						match: rule.RuleID,
					}
				} else {
					ruleResults <- ruleResult{
						score: 0,
					}
				}
			}(rule, word, domainStr)
		}
	}

	go func() {
		wg.Wait()
		close(ruleResults)
	}()

	for result := range ruleResults {
		if result.score > 0 {
			mu.Lock()
			logMessage.Score += result.score
			logMessage.Matches = append(logMessage.Matches, result.match)
			mu.Unlock()
		}
	}
}

type ruleResult struct {
	score int
	match string
}
