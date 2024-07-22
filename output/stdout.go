package output

import (
	"github.com/codevault-llc/certshield/types"
	"github.com/codevault-llc/certshield/utils"
)

func InitStdout() {
	utils.Logger.Info("Initialized stdout output")
}

func SendToStdout(data types.LogMessage) {
	if data.Score > 20 {
		utils.Logger.Error(
			"Match found",
			"domain", data.Domain,
			"score", data.Score,
		)
	} else if data.Score > 10 {
		utils.Logger.Warn(
			"Match found",
			"domain", data.Domain,
			"score", data.Score,
		)
	} else {
		utils.Logger.Info(
			"Match found",
			"domain", data.Domain,
			"score", data.Score,
		)
	}
}
