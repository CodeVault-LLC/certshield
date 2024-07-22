package utils

import (
	"fmt"
	"math"
	"strings"
)

func CalculateEntropy(data string) float64 {
	entropy := 0.0
	for i := 0; i < 256; i++ {
		px := float64(strings.Count(data, fmt.Sprint(i))) / float64(len(data))
		if px > 0 {
			entropy += -px * math.Log2(px)
		}
	}
	return entropy
}
