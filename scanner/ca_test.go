package scanner

import "testing"

func TestIsFreeCA(t *testing.T) {
	tests := []struct {
		name   string
		issuer map[string]interface{}
		want   bool
	}{
		{
			name: "Free CA",
			issuer: map[string]interface{}{
				"O": "Let's Encrypt",
			},
			want: true,
		},
		{
			name: "Paid CA",
			issuer: map[string]interface{}{
				"O": "GoDaddy",
			},
			want: false,
		},
		{
			name: "Unknown CA",
			issuer: map[string]interface{}{
				"O": "Unknown CA",
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isFreeCA(tt.issuer); got != tt.want {
				t.Errorf("IsFreeCA() = %v, want %v", got, tt.want)
			}
		})
	}
}
