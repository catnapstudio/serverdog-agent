// Package ids creates the random ids used for sites and deployments.
package ids

import (
	"crypto/rand"
	"regexp"
)

const alphabet = "abcdefghijklmnopqrstuvwxyz234567"

var pattern = regexp.MustCompile(`^[a-z2-7]{12}$`)

// New returns 12 random characters from the lowercase base32 alphabet.
func New() string {
	buffer := make([]byte, 12)
	rand.Read(buffer)

	for i, b := range buffer {
		buffer[i] = alphabet[int(b)%len(alphabet)]
	}

	return string(buffer)
}

// Valid reports whether id has the shape New produces, so it is safe in paths and unit names.
func Valid(id string) bool {
	return pattern.MatchString(id)
}
