package deploy

import (
	"reflect"
	"testing"
)

func TestFilterSeparatesMarkersFromText(t *testing.T) {
	data := []byte("==> Running the deploy script\n\x1eserverdog:abc:composer install\nInstalling dependencies\n\x1eserverdog:abc:npm ci\nadded 12 packages\npartial line")

	pieces, consumed := Filter(data, "abc", false)
	want := []Piece{
		{Text: "==> Running the deploy script\n", End: 30},
		{Command: "composer install", End: 62},
		{Text: "Installing dependencies\n", End: 86},
		{Command: "npm ci", End: 108},
		{Text: "added 12 packages\n", End: 126},
	}

	if !reflect.DeepEqual(pieces, want) {
		t.Errorf("pieces =\n%+v\nwant\n%+v", pieces, want)
	}
	if consumed != 126 {
		t.Errorf("consumed = %d; the partial last line must wait", consumed)
	}

	final, consumed := Filter(data[126:], "abc", true)
	if len(final) != 1 || final[0].Text != "partial line" || consumed != len(data)-126 {
		t.Errorf("final = %+v, consumed %d", final, consumed)
	}
}

func TestFilterKeepsForgedMarkers(t *testing.T) {
	data := []byte("\x1eserverdog:wrong:rm -rf /\nreal output\n")

	pieces, _ := Filter(data, "abc", false)
	if len(pieces) != 1 || pieces[0].Command != "" || pieces[0].Text != string(data) {
		t.Errorf("pieces = %+v", pieces)
	}
}

func TestFilterFindsAMarkerInTheMiddleOfALine(t *testing.T) {
	data := []byte("partial output\x1eserverdog:abc:npm ci\nnext\n")

	pieces, consumed := Filter(data, "abc", false)
	want := []Piece{
		{Text: "partial output", End: 14},
		{Command: "npm ci", End: 36},
		{Text: "next\n", End: 41},
	}

	if !reflect.DeepEqual(pieces, want) || consumed != 41 {
		t.Errorf("pieces =\n%+v\nwant\n%+v, consumed %d", pieces, want, consumed)
	}
}

func TestFilterKeepsAForgedMarkerInTheMiddleOfALine(t *testing.T) {
	data := []byte("output \x1eserverdog:wrong:rm -rf /\n")

	pieces, _ := Filter(data, "abc", false)
	if len(pieces) != 1 || pieces[0].Command != "" || pieces[0].Text != string(data) {
		t.Errorf("pieces = %+v", pieces)
	}
}

func TestMarkerForMultiLineCommand(t *testing.T) {
	// bash prints multi-line commands with their newlines replaced by spaces (see scriptRunner).
	data := []byte("\x1eserverdog:abc:if [ -f artisan ]; then  php artisan migrate; fi\n")

	pieces, _ := Filter(data, "abc", false)
	if len(pieces) != 1 || pieces[0].Command != "if [ -f artisan ]; then  php artisan migrate; fi" {
		t.Errorf("pieces = %+v", pieces)
	}
}
