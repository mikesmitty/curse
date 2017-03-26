package main

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
)

func loadPrincipalMap(conf config) (map[string]string, error) {
	file, err := os.Open(conf.PrincipalAliases)
	if err != nil {
		err = fmt.Errorf("Failed to open principalaliases file: '%v'", err)
		return nil, err
	}
	defer file.Close()

	principalMap := make(map[string]string)

	scanner := bufio.NewScanner(file)
Line:
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 || line[0] == '#' {
			continue
		}

		// Split line into principal/group aliases on colon
		parts := bytes.Split(line, []byte{':'})
		if len(parts) < 2 {
			continue
		}

		// Split groups on comma
		groups := bytes.Split(parts[1], []byte{','})
		if len(groups) < 1 {
			continue
		}

		prin := string(parts[0])

		// Check for wildcard groups
		for _, v := range groups {
			// If we got a wildcard, ignore everything else
			if bytes.Compare(v, []byte{'*'}) == 0 {
				principalMap[prin] = "*"
				continue Line
			}
		}

		principalMap[prin] = string(parts[1])
	}

	return principalMap, nil
}
