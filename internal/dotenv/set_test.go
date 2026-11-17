package dotenv

import (
	"slices"
	"testing"
)

func TestSetReplacesInPlace(t *testing.T) {
	content := "APP_NAME=Orchard\n# Database\nDB_HOST=localhost\nDB_PORT=3306\n"

	got := string(Set([]byte(content), "DB_HOST", "127.0.0.1"))
	if got != "APP_NAME=Orchard\n# Database\nDB_HOST=127.0.0.1\nDB_PORT=3306\n" {
		t.Errorf("got %q", got)
	}
}

func TestSetAppendsMissingKeys(t *testing.T) {
	if got := string(Set([]byte("APP_NAME=Orchard"), "DB_HOST", "127.0.0.1")); got != "APP_NAME=Orchard\nDB_HOST=127.0.0.1\n" {
		t.Errorf("got %q", got)
	}
	if got := string(Set(nil, "DB_HOST", "127.0.0.1")); got != "DB_HOST=127.0.0.1\n" {
		t.Errorf("empty file: got %q", got)
	}
}

func TestSetKeepsCRLFAndExport(t *testing.T) {
	got := string(Set([]byte("A=1\r\nexport DB_HOST=localhost\r\n"), "DB_HOST", "127.0.0.1"))
	if got != "A=1\r\nexport DB_HOST=127.0.0.1\r\n" {
		t.Errorf("got %q", got)
	}

	if got := string(Set([]byte("A=1\r\n"), "B", "2")); got != "A=1\r\nB=2\r\n" {
		t.Errorf("append: got %q", got)
	}
}

func TestSetReplacesAMultiLineValueWhole(t *testing.T) {
	content := "DB_PASSWORD=\"first\nsecond\"\nNEXT=1\n"

	if got := string(Set([]byte(content), "DB_PASSWORD", "abc")); got != "DB_PASSWORD=abc\nNEXT=1\n" {
		t.Errorf("got %q", got)
	}
}

func TestSetReplacesEveryDuplicate(t *testing.T) {
	// Loaders disagree on whether the first or the last duplicate wins, so both get the new value.
	got := string(Set([]byte("DB_HOST=a\nX=1\nDB_HOST=b\n"), "DB_HOST", "127.0.0.1"))
	if got != "DB_HOST=127.0.0.1\nX=1\nDB_HOST=127.0.0.1\n" {
		t.Errorf("got %q", got)
	}
}

func TestSetQuotesValuesThatNeedIt(t *testing.T) {
	got := Set(nil, "APP_NAME", `My "App" #1 \ two`)

	if string(got) != "APP_NAME=\"My \\\"App\\\" #1 \\\\ two\"\n" {
		t.Errorf("got %q", got)
	}
	if parsed := Parse(got); !slices.Equal(parsed, []string{`APP_NAME=My "App" #1 \ two`}) {
		t.Errorf("round trip = %q", parsed)
	}
}

func TestSetDoesNotTouchSimilarKeys(t *testing.T) {
	got := string(Set([]byte("DB_HOST_READ=x\n#DB_HOST=y\n"), "DB_HOST", "z"))
	if got != "DB_HOST_READ=x\n#DB_HOST=y\nDB_HOST=z\n" {
		t.Errorf("got %q", got)
	}
}

func TestSetEscapesDollarSoAValueIsNeverExpanded(t *testing.T) {
	got := Set(nil, "K", "${A}")

	if string(got) != "K=\"\\${A}\"\n" {
		t.Errorf("got %q", got)
	}
}

func TestSetThenParseKeepsReferencesLiteral(t *testing.T) {
	values := []string{"${A}", "pa$word", "$", `\${A}`, `a\`, "x${A}y${A}", "${${A}}"}

	for _, value := range values {
		content := Set([]byte("A=x\nOTHER=1\n"), "K", value)

		want := []string{"A=x", "OTHER=1", "K=" + value}
		if got := Parse(content); !slices.Equal(got, want) {
			t.Errorf("value %q: file %q parsed to %q, want %q", value, content, got, want)
		}
	}
}
