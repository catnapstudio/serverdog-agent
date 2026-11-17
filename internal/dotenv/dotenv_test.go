package dotenv

import (
	"os/exec"
	"reflect"
	"testing"
)

func TestParseHandlesRealWorldFiles(t *testing.T) {
	content := "# Laravel\r\n" +
		"APP_NAME=Orchard\r\n" +
		"APP_KEY=base64:abc+def/ghi==\r\n" +
		"export APP_ENV=production\n" +
		"  SPACED = value  \n" +
		"DB_PASSWORD=\"p#ss word \\\"quoted\\\"\"\n" +
		"SINGLE='literal $HOME \\n'\n" +
		"COMMENTED=value # trailing comment\n" +
		"URL=https://example.com/?a=b#frag\n" +
		"EMPTY=\n" +
		"MULTI=\"line one\\nline two\"\n" +
		"not a variable\n" +
		"1BAD=x\n" +
		"\n"

	want := []string{
		"APP_NAME=Orchard",
		"APP_KEY=base64:abc+def/ghi==",
		"APP_ENV=production",
		"SPACED=value",
		`DB_PASSWORD=p#ss word "quoted"`,
		`SINGLE=literal $HOME \n`,
		"COMMENTED=value",
		"URL=https://example.com/?a=b#frag",
		"EMPTY=",
		"MULTI=line one\nline two",
	}

	if got := Parse([]byte(content)); !reflect.DeepEqual(got, want) {
		t.Errorf("Parse =\n%q\nwant\n%q", got, want)
	}
}

func TestParseJoinsQuotedValuesThatSpanLines(t *testing.T) {
	content := "PRIVATE_KEY=\"-----BEGIN PRIVATE KEY-----\n" +
		"MIIEvQIBADANBgkqhkiG9w0BAQEFAASC\n" +
		"# not a comment, part of the key\n" +
		"-----END PRIVATE KEY-----\"\n" +
		"TOKEN=abc==\n"

	want := []string{
		"PRIVATE_KEY=-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASC\n# not a comment, part of the key\n-----END PRIVATE KEY-----",
		"TOKEN=abc==",
	}

	if got := Parse([]byte(content)); !reflect.DeepEqual(got, want) {
		t.Errorf("Parse =\n%q\nwant\n%q", got, want)
	}
}

func TestParseSingleQuotedValueSpanningLinesWithCRLF(t *testing.T) {
	content := "A='one\r\ntwo'\r\nB=1\r\n"

	want := []string{"A=one\ntwo", "B=1"}

	if got := Parse([]byte(content)); !reflect.DeepEqual(got, want) {
		t.Errorf("Parse = %q, want %q", got, want)
	}
}

func TestParseUnclosedQuoteTakesTheRestOfTheFile(t *testing.T) {
	content := "A=\"open\nB=2\nC=3"

	want := []string{"A=open\nB=2\nC=3"}

	if got := Parse([]byte(content)); !reflect.DeepEqual(got, want) {
		t.Errorf("Parse = %q, want %q", got, want)
	}
}

func TestParseEmptyValueFollowedByComment(t *testing.T) {
	if got := Parse([]byte("EMPTY= # nothing here\n")); !reflect.DeepEqual(got, []string{"EMPTY="}) {
		t.Errorf("Parse = %q", got)
	}
}

func TestParseStripsByteOrderMark(t *testing.T) {
	if got := Parse([]byte("\uFEFFFIRST=1\nSECOND=2\n")); !reflect.DeepEqual(got, []string{"FIRST=1", "SECOND=2"}) {
		t.Errorf("Parse = %q", got)
	}
}

func TestExportsRoundTripsHostileValues(t *testing.T) {
	value := "it's \"quoted\" $HOME `id` back\\slash\nsecond line"

	exports := Exports([]string{"HOSTILE=" + value}, func(string) bool { return false })

	out, err := exec.Command("sh", "-c", `eval "$1"; printf %s "$HOSTILE"`, "sh", exports).Output()
	if err != nil {
		t.Fatalf("eval of %q failed: %v", exports, err)
	}
	if string(out) != value {
		t.Errorf("round trip = %q, want %q", out, value)
	}
}

func TestExportsSkipsSetAndNonShellKeys(t *testing.T) {
	assignments := []string{"PATH=/evil", "dotted.key=1", "1BAD=2", "OK=yes", "NEXT=two=2"}

	exports := Exports(assignments, func(key string) bool { return key == "PATH" })

	want := "export OK='yes'\nexport NEXT='two=2'"
	if exports != want {
		t.Errorf("Exports = %q, want %q", exports, want)
	}
}

func TestParseExpandsReferences(t *testing.T) {
	t.Setenv("MISSING", "leaked from the process environment")
	t.Setenv("LATER", "leaked from the process environment")
	t.Setenv("NOPE", "leaked from the process environment")

	cases := []struct {
		name    string
		content string
		want    []string
	}{
		{
			name:    "1 Laravel's stock MAIL_FROM_NAME",
			content: "APP_NAME=Orchard\nMAIL_FROM_NAME=\"${APP_NAME}\"\n",
			want:    []string{"APP_NAME=Orchard", "MAIL_FROM_NAME=Orchard"},
		},
		{
			name:    "2 unquoted values expand",
			content: "A=x\nB=${A}/y\n",
			want:    []string{"A=x", "B=x/y"},
		},
		{
			name:    "3 single quotes are literal",
			content: "A=x\nB='${A}'\n",
			want:    []string{"A=x", "B=${A}"},
		},
		{
			name:    "4 an escaped dollar stays literal",
			content: "A=x\nB=\"\\${A}\"\n",
			want:    []string{"A=x", "B=${A}"},
		},
		{
			name:    "5a a bare $VAR is never expanded, unquoted",
			content: "A=x\nB=$A\n",
			want:    []string{"A=x", "B=$A"},
		},
		{
			name:    "5b a bare $VAR is never expanded, double-quoted",
			content: "A=x\nB=\"$A\"\n",
			want:    []string{"A=x", "B=$A"},
		},
		{
			name:    "6 an undefined key stays verbatim and the process environment is ignored",
			content: "B=\"${MISSING}\"\n",
			want:    []string{"B=${MISSING}"},
		},
		{
			name:    "7 a key assigned later stays verbatim",
			content: "B=\"${LATER}\"\nLATER=1\n",
			want:    []string{"B=${LATER}", "LATER=1"},
		},
		{
			name:    "8 a defined empty key expands to nothing",
			content: "A=\nB=\"[${A}]\"\n",
			want:    []string{"A=", "B=[]"},
		},
		{
			name:    "9 defaults are left as literal text",
			content: "A=x\nB=\"${A:-d}\"\nC=\"${NOPE:-d}\"\n",
			want:    []string{"A=x", "B=${A:-d}", "C=${NOPE:-d}"},
		},
		{
			name:    "10 several references in one value",
			content: "A=x\nB=1\nC=\"${A}-${B}-${A}\"\n",
			want:    []string{"A=x", "B=1", "C=x-1-x"},
		},
		{
			name:    "11 a key that refers to itself stays literal",
			content: "A=${A}\n",
			want:    []string{"A=${A}"},
		},
		{
			name:    "12 nested references resolve right to left",
			content: "N=ONE\nONE=hello\nB=\"${${N}}\"\n",
			want:    []string{"N=ONE", "ONE=hello", "B=hello"},
		},
		{
			name:    "13 substituted text is not scanned again",
			content: "A=${B}\nB=x\nC=${A}\n",
			want:    []string{"A=${B}", "B=x", "C=${B}"},
		},
		{
			name:    "14 a dollar that isn't a reference is untouched",
			content: "A=x\nP=\"pa$word${A}\"\n",
			want:    []string{"A=x", "P=pa$wordx"},
		},
		{
			name:    "15 escapes and references in the same value",
			content: "A=x\nB=\"${A}\\n${A}\"\n",
			want:    []string{"A=x", "B=x\nx"},
		},
		{
			name:    "16 a trailing comment is stripped first",
			content: "A=x\nB=${A} # note\n",
			want:    []string{"A=x", "B=x"},
		},
		{
			name:    "17 a quoted value that spans lines",
			content: "A=x\nK=\"${A}\nline2\"\n",
			want:    []string{"A=x", "K=x\nline2"},
		},
		{
			name:    "18 multibyte values",
			content: "A=ū\nB=\"${A}${A}\"\n",
			want:    []string{"A=ū", "B=ūū"},
		},
		{
			name:    "extra a reference uses the last earlier assignment",
			content: "A=one\nB=${A}\nA=two\nC=${A}\n",
			want:    []string{"A=one", "B=one", "A=two", "C=two"},
		},
		{
			name:    "extra a key can start from its own earlier value",
			content: "PATH_X=/a\nPATH_X=\"${PATH_X}:/b\"\n",
			want:    []string{"PATH_X=/a", "PATH_X=/a:/b"},
		},
		{
			name:    "extra a name with dots and digits",
			content: "my.key_2=v\nB=\"${my.key_2}\"\n",
			want:    []string{"my.key_2=v", "B=v"},
		},
		{
			name:    "extra an unclosed reference stays literal",
			content: "A=x\nB=\"${A\"\nC=${}\n",
			want:    []string{"A=x", "B=${A", "C=${}"},
		},
		{
			name:    "extra an export prefix and CRLF",
			content: "export A=x\r\nexport B=\"${A}\"\r\n",
			want:    []string{"A=x", "B=x"},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := Parse([]byte(c.content)); !reflect.DeepEqual(got, c.want) {
				t.Errorf("Parse(%q) =\n%q\nwant\n%q", c.content, got, c.want)
			}
		})
	}
}

func TestReferencesToEachOtherStopGrowingAValue(t *testing.T) {
	content := "A0=0123456789\n"
	for i := 1; i <= 40; i++ {
		content += "A" + string(rune('0'+i/10)) + string(rune('0'+i%10)) + "=${P}${P}\n"
		content = replaceLast(content, "${P}${P}", "${A"+prev(i)+"}${A"+prev(i)+"}")
	}

	total := 0
	for _, assignment := range Parse([]byte(content)) {
		total += len(assignment)
	}

	if total > 41*(maxValue+8) {
		t.Fatalf("40 doubling lines parsed to %d bytes", total)
	}
}

func prev(i int) string {
	if i == 1 {
		return "0"
	}
	return string(rune('0'+(i-1)/10)) + string(rune('0'+(i-1)%10))
}

func replaceLast(s, old, new string) string {
	i := len(s) - len(old) - 1
	return s[:i] + new + s[i+len(old):]
}
