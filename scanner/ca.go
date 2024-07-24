package scanner

import (
	"bufio"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/codevault-llc/certshield/utils"
	"github.com/jmoiron/jsonq"
)

func ScanCA(jq jsonq.JsonQuery) (int, []string) {
	var matches []string
	var score int

	issuerInterface, err := jq.Interface("data", "leaf_cert", "issuer")
	if err != nil {
		utils.Logger.Error("Error getting issuer", slog.String("error", err.Error()))
		return 0, matches
	}

	issuer, ok := issuerInterface.(map[string]interface{})
	if !ok {
		utils.Logger.Error("Error parsing issuer")
		return 0, matches
	}

	notBefore, err := jq.Float("data", "leaf_cert", "not_before")
	if err != nil {
		utils.Logger.Error("Error getting not before")
		return 0, matches
	}

	notAfter, err := jq.Float("data", "leaf_cert", "not_after")
	if err != nil {
		utils.Logger.Error("Error getting not after", slog.String("error", err.Error()))
		return 0, matches
	}

	if isFreeCA(issuer) {
		matches = append(matches, "Free CA")
		score += 10
	}

	if !isRecognizedCA(issuer) {
		matches = append(matches, "Not Recognized CA")
		score += 5
	}

	if isSelfSigned(issuer) {
		matches = append(matches, "Self-signed")
		score += 10
	}

	if IsShortValidationPeriod(time.Unix(int64(notBefore), 0), time.Unix(int64(notAfter), 0)) {
		matches = append(matches, "Short Validation Period")
		score += 5
	}

	return score, matches
}

func isFreeCA(issuer map[string]interface{}) bool {
	var freeCAs = []string{
		"Let's Encrypt",
		"Cloudflare Inc ECC CA-3",
		"Cloudflare Inc ECC CA-2",
		"Cloudflare Inc ECC CA-1",
	}

	if err := os.MkdirAll("./logs", 0755); err != nil {
		panic(err)
	}

	f, err := os.OpenFile("./logs/issuers.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		panic(err)
	}
	defer f.Close()

	issuerName, ok := issuer["O"].(string)
	if !ok {
		return false
	}

	existingIssuers, err := readIssuers("./logs/issuers.txt")
	if err != nil {
		panic(err)
	}

	counter := 1
	for i, entry := range existingIssuers {
		parts := strings.SplitN(entry, " (", 2)
		if parts[0] == issuerName {
			if len(parts) == 2 {
				_, err := fmt.Sscanf(parts[1], "%d)", &counter)
				if err != nil {
					panic(err)
				}
				counter++
			} else {
				counter = 2
			}
			existingIssuers[i] = fmt.Sprintf("%s (%d)", issuerName, counter)
			if err := writeIssuers("./logs/issuers.txt", existingIssuers); err != nil {
				panic(err)
			}
			break
		}
	}

	if counter == 1 {
		if _, err := f.WriteString(issuerName + "\n"); err != nil {
			panic(err)
		}
	}

	for _, ca := range freeCAs {
		if issuerName == ca {
			return true
		}
	}

	return false
}

func isRecognizedCA(issuer map[string]interface{}) bool {
	var recognizedCAs = []string{
		"DigiCert Inc",
		"GlobalSign nv-sa",
		"Google Trust Services",
		"Amazon",
		"Microsoft Corporation",
		"GoDaddy.com, Inc.",
		"Cloudflare Inc",
		"Let's Encrypt",
		"Cloudflare Inc ECC CA-3",
		"Cloudflare Inc ECC CA-2",
		"Cloudflare Inc ECC CA-1",

		"Starfield Technologies Inc.",
		"Network Solutions L.L.C.",
		"Thawte, Inc.",
		"GeoTrust Inc.",
		"VeriSign, Inc.",
		"Symantec Corporation",
		"Entrust, Inc.",
		"Comodo CA Limited",
		"IdenTrust, Inc.",
		"SecureTrust Corporation",
		"USERTrust RSA Certification Authority",
		"USERTrust ECC Certification Authority",
		"AddTrust External CA Root",
		"GlobalSign Root CA",
	}

	issuerName, ok := issuer["O"].(string)
	if !ok {
		return false
	}

	for _, ca := range recognizedCAs {
		if issuerName == ca {
			return true
		}
	}

	return false
}

func isSelfSigned(issuer map[string]interface{}) bool {
	if _, ok := issuer["CN"]; ok {
		return issuer["CN"] == issuer["O"]
	}

	return false
}

func IsShortValidationPeriod(notBefore time.Time, notAfter time.Time) bool {
	return notAfter.Sub(notBefore).Hours() < 90*24
}

func readIssuers(filename string) ([]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var issuers []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		issuers = append(issuers, scanner.Text())
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return issuers, nil
}

func writeIssuers(filename string, issuers []string) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	for _, issuer := range issuers {
		if _, err := file.WriteString(issuer + "\n"); err != nil {
			return err
		}
	}

	return nil
}
