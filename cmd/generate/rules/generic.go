package rules

import (
	"github.com/codevault-llc/certshield/config"
)

func GenericKeywords() *config.Rule {
	r := config.Rule{
		Description: "Generic rule for detecting general words",
		RuleID:      "generic-keywords",
		Words: 			[]string{"login", "log-in", "sign-in", "signin", "account", "verification", "verify", "webscr", "password",
		"credential", "support", "update", "authentication", "authenticate", "wallet", "alert", "purchase", "payment", "invoice",
		"transaction", "recover", "unlock", "live", "office", "form", "safe", "online", "portal", "secure", "security", "access", "verify",
		"verify-email", "verify-email-address", "verify-email-addresses", "verify-emails", "verify-emails-address"},
		Keywords:    []string{"generic", "keywords", "suspicious"},
		Score: 		 10,
	}

	// validate
	tps := []string{
		"login.google.com",
		"login.microsoft.com",
		"login.apple.com",
		"login.amazon.com",

		"signin.google.com",
		"signin.microsoft.com",

		"account.google.com",

		"verification.google.com",

		"password.google.com",

		"credential.google.com",
	}
	return validate(r, tps, nil)
}
