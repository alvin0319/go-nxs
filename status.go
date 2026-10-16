package nxs

import (
	"strconv"
	"strings"
	"unicode/utf8"
)

// parsePong parses the RakNet-format pong data of a listener into listing metadata.
func parsePong(b []byte) (*serverStatus, bool) {
	fields := strings.Split(string(b), ";")
	if len(fields) < 9 || fields[0] != "MCPE" {
		return nil, false
	}
	maxPlayers, err := strconv.Atoi(fields[5])
	if err != nil {
		return nil, false
	}
	s := &serverStatus{
		Name:           listingText(fields[1]),
		Level:          listingText(fields[7]),
		MaxPlayerCount: min(max(maxPlayers, 0), 1000000),
	}
	switch strings.ToLower(fields[8]) {
	case "creative", "1":
		s.GameType = 1
	case "adventure", "2":
		s.GameType = 2
	}
	if s.Name == "" {
		return nil, false
	}
	return s, true
}

// listingText removes characters not permitted in listing metadata and truncates it to 128 characters.
func listingText(s string) string {
	s = strings.ToValidUTF8(s, "")
	s = strings.Map(func(r rune) rune {
		if isControl(r) {
			return -1
		}
		return r
	}, s)
	if utf8.RuneCountInString(s) > 128 {
		s = string([]rune(s)[:128])
	}
	return s
}
