package main

import "testing"

func TestInvokedAsCreatorMenu(t *testing.T) {
	for _, tc := range []struct {
		program string
		want    bool
	}{
		{program: "npv-creator", want: true},
		{program: "/usr/local/bin/npv-creator", want: true},
		{program: "/usr/local/bin/creator-server", want: false},
		{program: "creator-server", want: false},
	} {
		if got := invokedAsCreatorMenu(tc.program); got != tc.want {
			t.Errorf("invokedAsCreatorMenu(%q) = %v, want %v", tc.program, got, tc.want)
		}
	}
}
