package rules

import (
	"fmt"
	"strings"

	"github.com/codevault-llc/certshield/config"
	"github.com/codevault-llc/certshield/scanner"
)

func validate(r config.Rule, truePositives []string, falsePositives []string) *config.Rule {
	var keywords []string
	for _, k := range r.Keywords {
		keywords = append(keywords, strings.ToLower(k))
	}
	r.Keywords = keywords

	rules := make(map[string]config.Rule)
	rules[r.RuleID] = r
	for _, tp := range truePositives {
		if len(scanner.GenericScan(r, tp)) != 1 {
			fmt.Println("Failed to validate", r.RuleID, tp)
		}
	}
	for _, fp := range falsePositives {
		if len(scanner.GenericScan(r, fp)) != 0 {
			fmt.Println("Failed to validate", r.RuleID, fp)
		}
	}
	return &r
}
