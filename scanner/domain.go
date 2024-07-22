package scanner

func IsSuspiciousTLD(domain string) bool {
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

func IsSuspiciousLength(domain string) bool {
	return len(domain) >= 50
}
