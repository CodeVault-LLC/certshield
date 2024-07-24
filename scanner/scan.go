package scanner

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/codevault-llc/certshield/config"
	"github.com/codevault-llc/certshield/output"
	"github.com/codevault-llc/certshield/types"
	"github.com/codevault-llc/certshield/utils"
	"github.com/jmoiron/jsonq"
)

func GenericScan(r config.Rule, match string) []string {
	var matches []string

	for _, word := range r.Words {
		if len(word) > 0 && len(match) > 0 {
			if len(word) > len(match) {
				if word[:len(match)] == match {
					matches = append(matches, word)
				}
			} else {
				if match[:len(word)] == word {
					matches = append(matches, word)
				}
			}
		}
	}

	fmt.Println("Matches: ", matches)
	return matches
}

func EndsWithScan(r config.Rule, match string) []string {
	var matches []string

	for _, word := range r.Words {
		if len(word) > 0 && len(match) > 0 {
			if len(word) > len(match) {
				if word[len(word)-len(match):] == match {
					matches = append(matches, word)
				}
			}
		}
	}

	fmt.Println("Matches: ", matches)
	return matches
}

func Scan(jq jsonq.JsonQuery, rules []config.Rule, scanPage bool) {
	updateType, err := jq.String("data", "update_type")
	if err != nil {
		utils.Logger.Error("Error getting update type", slog.String("error", err.Error()))
		return
	}

	if updateType == "PrecertLogEntry" {
		return
	} else if updateType == "PrecertEntryWithProof" {
		return
	} else if updateType == "X509LogEntry" {

		leafCert, err := jq.Interface("data", "leaf_cert")
		if err != nil {
			utils.Logger.Error("Error getting leaf certificate", slog.String("error", err.Error()))
			return
		}

		issuerInterface, err := jq.Interface("data", "leaf_cert", "issuer")
		if err != nil {
			utils.Logger.Error("Error getting issuer", slog.String("error", err.Error()))
			return
		}

		issuer, ok := issuerInterface.(map[string]interface{})
		if !ok {
			utils.Logger.Error("Error parsing issuer")
			return
		}

		allDomains, err := jq.Array("data", "leaf_cert", "all_domains")
		if err != nil {
			utils.Logger.Error("Error getting all domains", slog.String("error", err.Error()))
			return
		}

		for _, domain := range allDomains {
			domainStr := domain.(string)

			if scanPage {
				validUrl := utils.ValidateURL(domainStr)
				statusCode, error := utils.GetWebsite(validUrl)

				if error != "" {
					return
				}

				if !utils.ValidateResponse(statusCode) {
					return
				}
			}

			subjectOrg, ok := jq.String("data", "leaf_cert", "subject", "O")
			if ok != nil {
				subjectOrg = "N/A"
			}

			organizationUnit, ok := jq.String("data", "leaf_cert", "subject", "OU")
			if ok != nil {
				organizationUnit = "N/A"
			}

			subjectCommonName, ok := jq.String("data", "leaf_cert", "subject", "CN")
			if ok != nil {
				subjectCommonName = "N/A"
			}

			certificate, err := json.MarshalIndent(leafCert, "", "\t")
			if err != nil {
				utils.Logger.Error("Error marshalling certificate", slog.String("error", err.Error()))
			}

			logMessage := types.LogMessage{
				Timestamp: time.Now().UTC(),
				Domain:    domainStr,
				Vendor:    utils.GetSeverity(0),

				Score:   0,
				Matches: []string{},

				IssuerCommonName:    issuer["CN"].(string),
				SubjectCommonName:   subjectCommonName,
				IssuerOrganization:  issuer["O"].(string),
				SubjectOrganization: subjectOrg,

				SerialNumber: leafCert.(map[string]interface{})["serial_number"].(string),
				NotBefore:    time.Unix(int64(leafCert.(map[string]interface{})["not_before"].(float64)), 0),
				NotAfter:     time.Unix(int64(leafCert.(map[string]interface{})["not_after"].(float64)), 0),

				KeyUsage:           leafCert.(map[string]interface{})["extensions"].(map[string]interface{})["keyUsage"].(string),
				ExtendedKeyUsage:   leafCert.(map[string]interface{})["extensions"].(map[string]interface{})["extendedKeyUsage"].(string),
				SignatureAlgorithm: leafCert.(map[string]interface{})["signature_algorithm"].(string),

				OrganizationUnit: organizationUnit,

				Certificate:      string(certificate),
				IsExpired:        time.Now().UTC().After(time.Unix(int64(leafCert.(map[string]interface{})["not_after"].(float64)), 0)),
				IsRevoked:        false,
				IsWildcard:       domainStr[0] == '*',
				IssuanceDate:     time.Unix(int64(leafCert.(map[string]interface{})["not_before"].(float64)), 0),
				ValidationMethod: "N/A",
				Country:          "N/A",
				IPAddress:        "N/A",
				CertSource:       "CertStream",
				Notes:            "N/A",
			}

			if logMessage.IsExpired {
				logMessage.Score += 15
				logMessage.Matches = append(logMessage.Matches, "Expired")
			}

			// Scan for Certification CA.
			scannedCAScore, scannedCAMatches := ScanCA(jq)
			logMessage.Score += scannedCAScore
			logMessage.Matches = append(logMessage.Matches, scannedCAMatches...)

			scannedDomainScore, scannedDomainMatches := ScanDomain(domainStr)
			logMessage.Score += scannedDomainScore
			logMessage.Matches = append(logMessage.Matches, scannedDomainMatches...)

			if isSuspiciousTLD(domainStr) {
				logMessage.Score += 5
				logMessage.Matches = append(logMessage.Matches, "SuspiciousTLD")
			}

			if domainStr[0] == '*' {
				domainStr = domainStr[2:]
			}

			if isSuspiciousLength(domainStr) {
				logMessage.Score += 5
				logMessage.Matches = append(logMessage.Matches, "SuspiciousLength")
			}

			for _, rule := range rules {
				for range rule.Words {
					scan := GenericScan(rule, domainStr)

					if len(scan) > 0 {
						logMessage.Score += 1
						logMessage.Matches = append(logMessage.Matches, rule.RuleID)
					}
				}
			}

			if logMessage.Score > 0 {
				logMessage.Entropy = utils.CalculateEntropy(logMessage.Score)
				logMessage.Domain = domainStr
				logMessage.ValidationMethod = GetCertValidationType(leafCert.(map[string]interface{})["extensions"].(map[string]interface{})["certificatePolicies"].(string))

				output.SendToOutput(logMessage)
			}
		}
	}
}
