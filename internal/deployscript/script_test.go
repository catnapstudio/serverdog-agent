package deployscript

import (
	"errors"
	"strings"
	"testing"
)

const laravel = `echo before

$CREATE_RELEASE()

cd $SERVERDOG_RELEASE_DIRECTORY
$SERVERDOG_COMPOSER install --no-dev
  $ACTIVATE_RELEASE()  

$RESTART_QUEUES()
echo after
`

func TestSplitAtMacros(t *testing.T) {
	segments, err := Split(laravel)
	if err != nil {
		t.Fatal(err)
	}

	if strings.TrimSpace(segments.Before) != "echo before" {
		t.Errorf("before = %q", segments.Before)
	}
	if !strings.Contains(segments.Build, "$SERVERDOG_COMPOSER install --no-dev") || strings.Contains(segments.Build, "ACTIVATE") {
		t.Errorf("build = %q", segments.Build)
	}
	if !strings.Contains(segments.After, `"$SERVERDOG_PHP" artisan queue:restart`) || !strings.Contains(segments.After, "echo after") {
		t.Errorf("after = %q", segments.After)
	}
	if strings.Contains(segments.After, "$RESTART_QUEUES()") {
		t.Errorf("macro left in: %q", segments.After)
	}
}

func TestSplitKeepsLineNumbersForBashErrors(t *testing.T) {
	segments, err := Split("$CREATE_RELEASE()\necho one\n$ACTIVATE_RELEASE()\necho two\n")
	if err != nil {
		t.Fatal(err)
	}

	// Lines outside a segment become blank, so bash's "line N" matches the editor.
	if segments.Build != "\necho one\n\n\n" {
		t.Errorf("build = %q", segments.Build)
	}
	if segments.After != "\n\n\necho two\n" {
		t.Errorf("after = %q", segments.After)
	}
}

func TestSplitRejectsBrokenScripts(t *testing.T) {
	cases := map[string]string{
		"missing create":   "echo hi\n$ACTIVATE_RELEASE()\n",
		"missing activate": "$CREATE_RELEASE()\necho hi\n",
		"wrong order":      "$ACTIVATE_RELEASE()\n$CREATE_RELEASE()\n",
		"twice":            "$CREATE_RELEASE()\n$CREATE_RELEASE()\n$ACTIVATE_RELEASE()\n",
	}

	for name, script := range cases {
		_, err := Split(script)

		var scriptErr *Error
		if !errors.As(err, &scriptErr) {
			t.Errorf("%s: err = %v, want *Error", name, err)
		}
	}
}

func TestInPlaceDropsReleaseMacros(t *testing.T) {
	got := InPlace(laravel)

	if strings.Contains(got, "CREATE_RELEASE") || strings.Contains(got, "ACTIVATE_RELEASE") || strings.Contains(got, "$RESTART_QUEUES()") {
		t.Errorf("macros left in: %q", got)
	}
	if !strings.Contains(got, "artisan queue:restart") || !strings.Contains(got, "echo before") {
		t.Errorf("script = %q", got)
	}
}

func TestMacroInsideALineIsNotAMacro(t *testing.T) {
	_, err := Split("echo '$CREATE_RELEASE()'\n$ACTIVATE_RELEASE()\n")
	if err == nil {
		t.Fatal("a quoted macro counted as the macro")
	}
}
