package utils

import (
	"math"
)

func CalculateEntropy(score int) float64 {
	return math.Log2(float64(score))
}
