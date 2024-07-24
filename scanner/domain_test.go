package scanner

import "testing"

func TestIsSuspiciousTLD(t *testing.T) {
	tests := []struct {
		name   string
		domain string
		want   bool
	}{
		{
			name:   "Suspicious TLD",
			domain: "example.xyz",
			want:   true,
		},
		{
			name:   "Non-Suspicious TLD",
			domain: "example.com",
			want:   false,
		},
		{
			name:   "Suspicious TLD",
			domain: "example.top",
			want:   true,
		},
		{
			name:   "Non-Suspicious TLD",
			domain: "example.net",
			want:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isSuspiciousTLD(tt.domain); got != tt.want {
				t.Errorf("IsSuspiciousTLD() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIsSuspiciousLength(t *testing.T) {
	tests := []struct {
		name   string
		domain string
		want   bool
	}{
		{
			name:   "Suspicious Length",
			domain: "exampleaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.com",
			want:   true,
		},
		{
			name:   "Non-Suspicious Length",
			domain: "example.com",
			want:   false,
		},
		{
			name:   "Suspicious Length",
			domain: "exampleaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.xyz",
			want:   true,
		},
		{
			name:   "Non-Suspicious Length",
			domain: "example.net",
			want:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isSuspiciousLength(tt.domain); got != tt.want {
				t.Errorf("IsSuspiciousLength() = %v, want %v", got, tt.want)
			}
		})
	}
}
