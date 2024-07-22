package rules

import (
	"github.com/codevault-llc/certshield/config"
)

func AppleKeywords() *config.Rule {
	r := config.Rule{
		Description: "Apple keywords",
		RuleID:      "apple-keywords",
		Words: 			[]string{
			"apple",
			"appleid",
			"apple-id",

			"itunes",
			"iforgot",
		},
		Keywords:    []string{"apple"},
		Score: 		 10,
	}

	// validate
	tps := []string{
		"apple.com",

		"itunes.apple.com",

		"iforgot.apple.com",
	}
	return validate(r, tps, nil)
}
