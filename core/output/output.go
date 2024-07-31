package output

import (
	"os"

	"github.com/codevault-llc/certshield/types"
)

var Outputs []string

// FindOutputs checks the environment variables to see which outputs are enabled
func findOutputs() {
	if os.Getenv("ELASTICSEARCH_URL") != "" {
		Outputs = append(Outputs, "elasticsearch")
	} else {
		Outputs = append(Outputs, "stdout")
	}
}

// SetupOutput initializes the output services
func SetupOutput() {
	findOutputs()

	for _, output := range Outputs {
		switch output {
		case "elasticsearch":
			InitElasticSearch()
		case "slack":
			// InitSlack()
		case "stdout":
			InitStdout()
		}
	}
}

func SendToOutput(data types.LogMessage) {
	for _, output := range Outputs {
		switch output {
		case "elasticsearch":
			SendToElasticSearch(data)
		case "slack":
			// SendToSlack(data)
		case "stdout":
			SendToStdout(data)
		}
	}
}
