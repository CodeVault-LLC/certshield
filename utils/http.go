package utils

import (
	"net/http"
)

// GetWebsite returns the status of a website
func GetWebsite(url string) (int, string) {
	response, err := http.Get(url)
	if err != nil {
		return 0, err.Error()
	}
	defer response.Body.Close()
	return response.StatusCode, ""
}

func ValidateURL(domain string) string {
	// http:// or https://
	if domain[:7] != "http://" && domain[:8] != "https://" {
		return "https://" + domain
	}

	return domain
}
