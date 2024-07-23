package rules

import (
	"github.com/codevault-llc/certshield/config"
)

func DatabaseTokens() *config.Rule {
	r := config.Rule{
		Description: "Rule for catching database domains",
		RuleID:      "database-keywords",
		Words: 			[]string{
			// Valid database domains (for different things amazon.)
		},
		Keywords:    []string{"database"},
		Score: 		 10,
	}

	// validate
	tps := []string{
		// Database equal domains.
	}
	return validate(r, tps, nil)
}
