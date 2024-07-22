package utils

import "testing"

func TestGetSeverity(t *testing.T) {
	tests := []struct {
		name string
		score int
		want string
	}{
		{
			name: "Very Dangerous",
			score: 20,
			want: "Very Dangerous",
		},
		{
			name: "Dangerous",
			score: 15,
			want: "Dangerous",
		},
		{
			name: "Suspicious",
			score: 5,
			want: "Suspicious",
		},
		{
			name: "Unknown",
			score: 0,
			want: "Unknown",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := GetSeverity(tt.score); got != tt.want {
				t.Errorf("GetSeverity() = %v, want %v", got, tt.want)
			}
		})
	}
}
