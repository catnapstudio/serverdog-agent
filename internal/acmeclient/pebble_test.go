//go:build pebble

package acmeclient

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/catnapstudio/serverdog-agent/internal/certs"
)

// Run with scripts/pebble-test.sh (Pebble with PEBBLE_VA_ALWAYS_VALID=1).
func TestObtainAndRenewalTimeFromPebble(t *testing.T) {
	dir := t.TempDir()
	client := &Lego{Directory: os.Getenv("PEBBLE_DIRECTORY"), CABundle: os.Getenv("PEBBLE_CA"), AccountDir: dir + "/account", Webroot: dir}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	for _, keyType := range []certs.KeyType{certs.ECDSAP256, certs.RSA2048} {
		issued, err := client.Obtain(ctx, []string{"pebble.serverdog.test", "www.pebble.serverdog.test"}, keyType)
		if err != nil {
			t.Fatalf("%s: %v", keyType, err)
		}
		if issued.Leaf.VerifyHostname("www.pebble.serverdog.test") != nil {
			t.Errorf("%s: names = %v", keyType, issued.Leaf.DNSNames)
		}
		if _, err := certs.ParseKey(issued.PrivateKey); err != nil {
			t.Errorf("%s key: %v", keyType, err)
		}

		if _, err := client.RenewalTime(ctx, issued.Leaf, time.Now()); err != nil {
			t.Errorf("%s renewal time: %v", keyType, err)
		}
	}
}
