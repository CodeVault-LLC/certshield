package constants

import "github.com/codevault-llc/certshield/config"

var VC config.ViperConfig

func InitConfig() {
	err := VC.ReadConfig()

	if err != nil {
		panic(err)
	}
}
