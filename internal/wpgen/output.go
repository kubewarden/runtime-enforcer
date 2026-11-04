package wpgen

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/jedib0t/go-pretty/v6/text"
	"golang.org/x/term"
)

const (
	colorFlag   = "color"
	colorAuto   = "auto"
	colorAlways = "always"
	colorNever  = "never"

	ansiReset  = "\x1b[0m"
	ansiBold   = "\x1b[1m"
	ansiRed    = "\x1b[31m"
	ansiGreen  = "\x1b[32m"
	ansiYellow = "\x1b[33m"
)

// globalOptions are the flags of the root command, and the access to the
// environment that the output depends on.
type globalOptions struct {
	Color string

	// getenv and isTerminal are os.Getenv and a terminal check. Tests
	// replace them.
	getenv     func(string) string
	isTerminal func(io.Writer) bool
}

func newGlobalOptions() *globalOptions {
	return &globalOptions{
		Color:      colorAuto,
		getenv:     os.Getenv,
		isTerminal: isTerminal,
	}
}

func (g *globalOptions) validate() error {
	switch g.Color {
	case colorAuto, colorAlways, colorNever:
		return nil
	default:
		return fmt.Errorf("invalid color mode %q: must be %q, %q or %q", g.Color, colorAuto, colorAlways, colorNever)
	}
}

// painter returns the painter for the output stream w.
//
// The rules follow the common conventions: --color=always and --color=never
// win. With --color=auto, a non-empty NO_COLOR disables colors, a non-empty
// CLICOLOR_FORCE other than "0" enables them, and otherwise colors are on
// only when w is a terminal.
func (g *globalOptions) painter(w io.Writer) painter {
	switch g.Color {
	case colorAlways:
		return painter{enabled: true}
	case colorNever:
		return painter{}
	}
	if g.getenv("NO_COLOR") != "" {
		return painter{}
	}
	if force := g.getenv("CLICOLOR_FORCE"); force != "" && force != "0" {
		return painter{enabled: true}
	}
	return painter{enabled: g.isTerminal(w)}
}

func isTerminal(w io.Writer) bool {
	f, ok := w.(*os.File)
	return ok && term.IsTerminal(int(f.Fd()))
}

// streams are the output streams of a command, with their painters.
type streams struct {
	out, err               io.Writer
	outPainter, errPainter painter
	// sameScreen is true when both streams are terminals, so that their
	// lines mix on one screen.
	sameScreen bool
}

func (g *globalOptions) streams(out, err io.Writer) streams {
	return streams{
		out:        out,
		err:        err,
		outPainter: g.painter(out),
		errPainter: g.painter(err),
		sameScreen: g.isTerminal(out) && g.isTerminal(err),
	}
}

// separate prints a blank line on standard error when both streams share the
// screen. It separates the messages on standard error from the output that
// follows on standard output. When standard output goes to a file, the blank
// line is not needed.
func (s streams) separate() {
	if s.sameScreen {
		fmt.Fprintln(s.err)
	}
}

// painter adds ANSI styles to text, when colors are enabled.
type painter struct {
	enabled bool
}

func (p painter) paint(s string, codes ...string) string {
	if !p.enabled || len(codes) == 0 {
		return s
	}
	return strings.Join(codes, "") + s + ansiReset
}

// success styles a positive verdict.
func (p painter) success(s string) string { return p.paint(s, ansiBold, ansiGreen) }

// failure styles a negative verdict.
func (p painter) failure(s string) string { return p.paint(s, ansiBold, ansiRed) }

// warning styles a warning word.
func (p painter) warning(s string) string { return p.paint(s, ansiBold, ansiYellow) }

// notice styles a notice that is easy to miss.
func (p painter) notice(s string) string { return p.paint(s, ansiYellow) }

// strong styles a name.
func (p painter) strong(s string) string { return p.paint(s, ansiBold) }

// headerContainer is the header of the container column of all the tables.
const headerContainer = "Container"

// newTable returns a table writer with the style of all the wpgen tables.
func newTable(header table.Row, configs ...table.ColumnConfig) table.Writer {
	t := table.NewWriter()
	t.SetStyle(table.StyleLight)
	t.AppendHeader(header)
	t.SetColumnConfigs(configs)
	return t
}

// alignRight returns the configurations that align the named columns to
// the right, for numbers.
func alignRight(names ...string) []table.ColumnConfig {
	configs := make([]table.ColumnConfig, 0, len(names))
	for _, name := range names {
		configs = append(configs, table.ColumnConfig{Name: name, Align: text.AlignRight})
	}
	return configs
}

// renderTable writes the table, followed by a new line.
func renderTable(w io.Writer, t table.Writer) {
	fmt.Fprintln(w, t.Render())
}

// stickyWriter keeps the first write error of w, and skips the writes after
// it. A report has many writes: the caller checks the error once, at the end.
type stickyWriter struct {
	w   io.Writer
	err error
}

func (s *stickyWriter) Write(p []byte) (int, error) {
	if s.err != nil {
		return 0, s.err
	}
	n, err := s.w.Write(p)
	s.err = err
	return n, err
}

// reportedError is an error that the command already reported to the user,
// so Execute does not print it again.
type reportedError struct {
	msg string
}

func (e *reportedError) Error() string { return e.msg }

// isReported reports if the error was already shown to the user.
func isReported(err error) bool {
	var reported *reportedError
	return errors.As(err, &reported)
}
