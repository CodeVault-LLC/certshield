package utils

func GetSeverity(score int) string {
	if score >= 20 {
		return "Very Dangerous"
	} else if score >= 10 {
		return "Dangerous"
	} else if score >= 5 {
		return "Suspicious"
	} else {
		return "Unknown"
	}
}
