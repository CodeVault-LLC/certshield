package scanner

import (
	"github.com/codevault-llc/certshield/config"
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

	return matches
}
