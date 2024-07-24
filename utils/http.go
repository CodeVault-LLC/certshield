package utils

import (
	"net/http"

	"github.com/lithammer/fuzzysearch/fuzzy"
)

func GetWebsite(url string) (int, string) {
	response, err := http.Get(url)
	if err != nil {
		return 0, err.Error()
	}
	defer response.Body.Close()
	return response.StatusCode, ""
}

func ValidateURL(domain string) string {
	if domain[:7] != "http://" && domain[:8] != "https://" {
		return "https://" + domain
	}

	return domain
}

func ValidateResponse(statusCode int) bool {
	if statusCode == 200 || (statusCode >= 301 && statusCode <= 303) || (statusCode >= 307 && statusCode <= 308) || statusCode == 410 || statusCode == 403 || statusCode == 401 || statusCode == 400 {
		return true
	}

	return false
}

func FilterDomain(domain string, filter string) bool {
	if filter == "" {
		return true
	}

	if fuzzy.Match(filter, domain) {
		return true
	}

	return false
}
