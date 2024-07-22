package scanner

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

func IsFreeCA(issuer map[string]interface{}) bool {
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
