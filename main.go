package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
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
			urls := collect(line, collectURL)
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

func collect(s string, collect func(string) (string, int)) []string {
	results := []string{}

	for from := 0; from < len(s); {
		result, next := collect(s[from:])
		if len(result) > 0 {
			results = append(results, result)
		}
		if next == -1 {
			break
		}
		from += next
	}

	return results
}
