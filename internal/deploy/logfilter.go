package deploy

import "bytes"

const markerPrefix = "\x1eserverdog:"

// Piece is display text or a command marker; End is the offset just after it within the filtered data.
type Piece struct {
	Text    string
	Command string
	End     int
}

// Filter turns raw log bytes into pieces. A line carrying this deployment's marker becomes a command, with any text
// before the marker kept as text; anything else, including forged markers, stays text. Without final, a trailing
// partial line is left for later.
func Filter(data []byte, marker string, final bool) ([]Piece, int) {
	prefix := []byte(markerPrefix + marker + ":")

	var pieces []Piece
	var text bytes.Buffer
	consumed := 0

	flush := func(end int) {
		if text.Len() > 0 {
			pieces = append(pieces, Piece{Text: text.String(), End: end})
			text.Reset()
		}
	}

	for consumed < len(data) {
		rest := data[consumed:]
		newline := bytes.IndexByte(rest, '\n')

		var line []byte
		switch {
		case newline >= 0:
			line = rest[:newline+1]
		case final:
			line = rest
		default:
			flush(consumed)
			return pieces, consumed
		}

		start := bytes.Index(line, prefix)
		if start < 0 {
			text.Write(line)
			consumed += len(line)
			continue
		}

		text.Write(line[:start])
		flush(consumed + start)

		consumed += len(line)
		command := bytes.TrimSuffix(line[start+len(prefix):], []byte("\n"))
		pieces = append(pieces, Piece{Command: string(command), End: consumed})
	}

	flush(consumed)

	return pieces, consumed
}
