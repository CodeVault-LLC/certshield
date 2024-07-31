package scanner

import "strings"

func ScanDomain(domain string) (int, []string) {
	var matches []string
	var score int

	if isSuspiciousTLD(domain) {
		matches = append(matches, "Suspicious TLD")
		score += 10
	}

	if isSuspiciousLength(domain) {
		matches = append(matches, "Suspicious Length")
		score += 10
	}

	if isDeeplyNested(domain) {
		matches = append(matches, "Deeply Nested")
		score += 10
	}

	if hasManyHyphens(domain) {
		matches = append(matches, "Many Hyphens")
		score += 10
	}

	return score, matches
}

func isSuspiciousTLD(domain string) bool {
	var suspiciousTLDs = []string{
		"xyz",
		"top",
		"loan",
		"work",
		"party",
		"click",
		"country",
		"stream",
		"gdn",
		"mom",
		"xin",
		"kim",
	}

	for _, tld := range suspiciousTLDs {
		if len(domain) >= len(tld) && domain[len(domain)-len(tld):] == tld {
			return true
		}
	}

	return false
}

func isSuspiciousLength(domain string) bool {
	return len(domain) >= 50
}

func isDeeplyNested(domain string) bool {
	return strings.Count(domain, ".") >= 3
}

func hasManyHyphens(domain string) bool {
	return !strings.Contains(domain, "xn--") && strings.Count(domain, "-") >= 4
}
