package main

import "testing"

func TestSqueezeURL(t *testing.T) {
	tables := []struct {
		in  string
		out string
	}{
		{"https://a.fr", "https://a.fr"},
		{"     https://a.fr       ", "https://a.fr"},
		{"lorem,https://a.fr'", "https://a.fr"},
	}

	for _, table := range tables {
		s, err := squeezeURL(table.in)
		if err != nil {
			t.Error(err)
		}
		if s != table.out {
			t.Fail()
		}
	}
}
