package main

import (
	"fmt"
	"os"
	"text/template"

	"github.com/codevault-llc/certshield/cmd/generate/rules"
	"github.com/codevault-llc/certshield/config"
)

const (
	templatePath = "rules/config.tmpl"
)

//go:generate go run $GOFILE ../../config/certshield.toml

func main() {
	if len(os.Args) < 2 {
		os.Stderr.WriteString("Specify path to the certshield.toml config\n")
		os.Exit(2)
	}
	certshieldConfigPath := os.Args[1]

	configRules := []*config.Rule{
		rules.GenericKeywords(),
		rules.AppleKeywords(),
	}

	// ensure rules have unique ids
	ruleLookUp := make(map[string]config.Rule, len(configRules))
	for _, rule := range configRules {
		if _, ok := ruleLookUp[rule.RuleID]; ok {
			fmt.Printf("RuleID %s already exists\n", rule.RuleID)
		}

		// TODO: eventually change all the signatures to get ride of this
		// nasty dereferencing.
		ruleLookUp[rule.RuleID] = *rule
	}

	tmpl, err := template.ParseFiles(templatePath)
	if err != nil {
		fmt.Println("Failed to parse template", err)
	}

	f, err := os.Create(certshieldConfigPath)
	if err != nil {
		fmt.Println("Failed to create file", err)
	}

	if err = tmpl.Execute(f, config.Config{Rules: ruleLookUp}); err != nil {
		fmt.Println("Failed to execute template", err)
	}
}
