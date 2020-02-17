package main

import (
	"regexp"
	"strings"

	"github.com/asaskevich/govalidator"
)

var urlSchemeRegexp = regexp.MustCompile("^[a-z](?:[a-z0-9+.-])*$")
var urlColonSlashSlash = "://"

func collectURL(s string) (string, int) {
	colonIdx := strings.Index(s, urlColonSlashSlash)
	if colonIdx == -1 {
		return "", -1
	}

	schemeIndex := -1
	for i := 1; colonIdx-i >= 0; i++ {
		scheme := s[(colonIdx - i):colonIdx]
		if !urlSchemeRegexp.MatchString(scheme) {
			break
		}
		schemeIndex = colonIdx - i
	}
	if schemeIndex == -1 {
		return "", schemeIndex + len(urlColonSlashSlash) + 1
	}

	var u string
	for i := colonIdx + len(urlColonSlashSlash); i < len(s); i++ {
		// some characters cannot be in last position
		if strings.ContainsRune("-.", rune(s[i])) {
			continue
		}
		if strings.ContainsRune("()[]", rune(s[i])) || !govalidator.IsURL("http://"+s[colonIdx+len(urlColonSlashSlash):i+1]) {
			break
		}
		u = s[schemeIndex : i+1]
	}

	return u, schemeIndex + len(u) + 1
}
