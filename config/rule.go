package config

type Rule struct {
	Description string
	RuleID      string

	Words []string

	Keywords []string
	Score    int
}
