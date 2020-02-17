package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"regexp"
	"strings"

	"github.com/asaskevich/govalidator"
)

func main() {
	pOne := flag.Bool("1", false, "if true stop after one result")
	pURL := flag.Bool("url", false, "if true do try to match urls")
	flag.Parse()

	reader := bufio.NewReader(os.Stdin)
	scanner := bufio.NewScanner(reader)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		if *pURL {
			urls := findURLs(line)
			for _, u := range urls {
				fmt.Println(u)
				if *pOne {
					return
				}
			}
		} else {
			log.Fatal(errors.New("specify at least one of: --url"))
		}
	}

	if err := scanner.Err(); err != nil {
		log.Fatal(err)
	}
}

var urlSchemeRegexp = regexp.MustCompile("^[a-z](?:[a-z0-9+.-])*$")
var urlColonSlashSlash = "://"

func findURLs(s string) []string {
	urls := []string{}

	for from := 0; from < len(s); {
		u, next := findURL(s[from:])
		if len(u) > 0 {
			urls = append(urls, u)
		}
		if next == -1 {
			break
		}
		from += next
	}

	return urls
}

func findURL(s string) (string, int) {
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
		if strings.ContainsRune("()[]", rune(s[i])) || !govalidator.IsURL("http://"+s[colonIdx+len(urlColonSlashSlash):i+1]) {
			break
		}
		u = s[schemeIndex : i+1]
	}

	return u, schemeIndex + len(u) + 1
}
