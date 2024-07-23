package config

import (
	_ "embed"
	"strings"

	"github.com/spf13/viper"
)

//go:embed certshield.toml
var DefaultConfig string

type ViperConfig struct {
	Description string

	Rules []struct {
		ID          string
		Description string

		Words []string

		Keywords []string
		Score    int
	}
}

type Config struct {
	Rules map[string]Rule
}

// Mainly read the config file and return the ViperConfig struct
func (vc *ViperConfig) ReadConfig() error {
	viper.SetConfigType("toml")
	viperError := viper.ReadConfig(strings.NewReader(DefaultConfig))

	if viperError != nil {
		return viperError
	}

	err := viper.Unmarshal(vc)
	if err != nil {
		return err
	}

	return nil
}

// Order the rules based on alphabetical order of the ID
func (vc *ViperConfig) OrderRules() []Rule {
	rules := make([]Rule, len(vc.Rules))

	for i, rule := range vc.Rules {
		rules[i] = Rule{
			Description: rule.Description,
			RuleID:      rule.ID,
			Words:       rule.Words,
			Keywords:    rule.Keywords,
		}
	}

	return rules
}
