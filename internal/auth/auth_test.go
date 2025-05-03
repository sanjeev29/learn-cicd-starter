package auth

import (
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	type test struct {
		name     string
		input    map[string][]string
		expected string
		errorStr string
	}

	tests := []test{
		{
			name:     "empty input",
			input:    map[string][]string{},
			expected: "",
			errorStr: "no authorization header included",
		},
		{
			name:     "empty value",
			input:    map[string][]string{"Authorization": {""}},
			expected: "",
			errorStr: "no authorization header included",
		},
		{
			name:     "no sep",
			input:    map[string][]string{"Authorization": {"ApiKey123456"}},
			expected: "",
			errorStr: "malformed authorization header",
		},
		{
			name:     "invalid auth prefix",
			input:    map[string][]string{"Authorization": {"apikey123456"}},
			expected: "",
			errorStr: "malformed authorization header",
		},
		{
			name:     "valid header",
			input:    map[string][]string{"Authorization": {"ApiKey 123456"}},
			expected: "123456",
			errorStr: "",
		},
	}

	for _, tc := range tests {
		got, err := GetAPIKey(tc.input)
		if err != nil {
			if err.Error() != tc.errorStr {
				t.Fatalf("%s: expected: %s, got: %s", tc.name, tc.errorStr, err.Error())
			}
		}

		if got != tc.expected {
			t.Fatalf("%s: expected: %s, got: %s", tc.name, tc.expected, got)
		}
	}
}
