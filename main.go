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
	pAll := flag.Bool("all", false, "if true do not stop after the first match")
	pURL := flag.Bool("url", false, "if true do try to match urls")
	flag.Parse()

	reader := bufio.NewReader(os.Stdin)
	scanner := bufio.NewScanner(reader)

	for scanner.Scan() {
		if *pURL {
			if s, err := squeezeURL(scanner.Text()); err == nil {
				fmt.Println(s)
				if !*pAll {
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

var urlScheme = regexp.MustCompile("^[a-z](?:[a-z0-9+.-])*$")
var urlColonSlashSlash = "://"

func squeezeURL(s string) (string, error) {
	i := strings.Index(s, urlColonSlashSlash)
	if i == -1 {
		return "", errors.New("cannot identify the :// pattern")
	}

	start := -1
	for j := 1; i-j >= 0; j++ {
		ss := s[(i - j):i]
		if urlScheme.MatchString(ss) {
			start = i - j
		} else {
			break
		}
	}
	if start == -1 {
		return "", errors.New("cannot find a scheme")
	}

	var u string
	for j := i + len(urlColonSlashSlash) + 1; j <= len(s); j++ {
		ss := s[start:j]
		if govalidator.IsURL(ss) {
			u = ss
		} else {
			break
		}
	}

	if len(u) == 0 {
		return "", errors.New("unable to extract url")
	}
	return u, nil
}
