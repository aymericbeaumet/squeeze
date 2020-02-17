package main

import (
	"reflect"
	"testing"
)

func TestSqueezeURLs(t *testing.T) {
	tables := []struct {
		in  string
		out []string
	}{
		{
			"http://a.fr",
			[]string{"http://a.fr"},
		},
		{
			"     http://b.fr       ",
			[]string{"http://b.fr"},
		},
		{
			"lorem,http://c.fr,ipsum",
			[]string{"http://c.fr"},
		},
		{
			"'http://d.fr'",
			[]string{"http://d.fr"},
		},
		{
			"'http://e.fr' 'https://f.fr'",
			[]string{"http://e.fr", "https://f.fr"},
		},
		{
			"http://foo|http://bar",
			[]string{"http://foo", "http://bar"},
		},
		{
			"://foo",
			[]string{},
		},
		{
			":// ftp://localhost",
			[]string{"ftp://localhost"},
		},
		{
			"[some markdown link](https://en.wikipedia.org/wiki/Markdown)",
			[]string{"https://en.wikipedia.org/wiki/Markdown"},
		},
		{
			`<html><body><a href="http://localhost"></a><a href="https://localhost"></a></body></html>`,
			[]string{"http://localhost", "https://localhost"},
		},
		{
			`{ "a": "http://github.com", "b": "https://github.com" }`,
			[]string{"http://github.com", "https://github.com"},
		},
		{
			`{ "a": "git://github.com", "b": "ssh://github.com" }`,
			[]string{"git://github.com", "ssh://github.com"},
		},
	}

	for _, table := range tables {
		out := findURLs(table.in)
		if !reflect.DeepEqual(out, table.out) {
			t.Errorf("expected %#v but got %#v\n", table.out, out)
		}
	}
}
