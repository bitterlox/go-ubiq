// Copyright 2016 The go-ethereum Authors
// This file is part of go-ethereum.
//
// go-ethereum is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// go-ethereum is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with go-ethereum. If not, see <http://www.gnu.org/licenses/>.

package main

import (
	"fmt"
	"io/ioutil"
	"os"
	"testing"

	"github.com/docker/docker/pkg/reexec"
	"github.com/ubiq/go-ubiq/internal/cmdtest"
)

func tmpdir(t *testing.T) string {
	dir, err := ioutil.TempDir("", "gubiq-test")
	if err != nil {
		t.Fatal(err)
	}
	return dir
}

<<<<<<< HEAD:cmd/gubiq/run_test.go
type testgubiq struct {
	// For total convenience, all testing methods are available.
	*testing.T
	// template variables for expect
	Datadir    string
	Executable string
	Etherbase  string
	Func       template.FuncMap
=======
type testgeth struct {
	*cmdtest.TestCmd
>>>>>>> ab5646c532292b51e319f290afccf6a44f874372:cmd/geth/run_test.go

	// template variables for expect
	Datadir   string
	Etherbase string
}

func init() {
<<<<<<< HEAD:cmd/gubiq/run_test.go
	// Run the app if we're the child process for runGubiq.
	if os.Getenv("GETH_TEST_CHILD") != "" {
=======
	// Run the app if we've been exec'd as "geth-test" in runGeth.
	reexec.Register("geth-test", func() {
>>>>>>> ab5646c532292b51e319f290afccf6a44f874372:cmd/geth/run_test.go
		if err := app.Run(os.Args); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		os.Exit(0)
	})
}

func TestMain(m *testing.M) {
	// check if we have been reexec'd
	if reexec.Init() {
		return
	}
	os.Exit(m.Run())
}

// spawns gubiq with the given command line args. If the args don't set --datadir, the
// child g gets a temporary data directory.
<<<<<<< HEAD:cmd/gubiq/run_test.go
func runGubiq(t *testing.T, args ...string) *testgubiq {
	tt := &testgubiq{T: t, Executable: os.Args[0]}
=======
func runGeth(t *testing.T, args ...string) *testgeth {
	tt := &testgeth{}
	tt.TestCmd = cmdtest.NewTestCmd(t, tt)
>>>>>>> ab5646c532292b51e319f290afccf6a44f874372:cmd/geth/run_test.go
	for i, arg := range args {
		switch {
		case arg == "-datadir" || arg == "--datadir":
			if i < len(args)-1 {
				tt.Datadir = args[i+1]
			}
		case arg == "-etherbase" || arg == "--etherbase":
			if i < len(args)-1 {
				tt.Etherbase = args[i+1]
			}
		}
	}
	if tt.Datadir == "" {
		tt.Datadir = tmpdir(t)
		tt.Cleanup = func() { os.RemoveAll(tt.Datadir) }
		args = append([]string{"-datadir", tt.Datadir}, args...)
		// Remove the temporary datadir if something fails below.
		defer func() {
			if t.Failed() {
				tt.Cleanup()
			}
		}()
	}

<<<<<<< HEAD:cmd/gubiq/run_test.go
	// Boot "gubiq". This actually runs the test binary but the init function
	// will prevent any tests from running.
	tt.stderr = &testlogger{t: t}
	tt.cmd = exec.Command(os.Args[0], args...)
	tt.cmd.Env = append(os.Environ(), "GETH_TEST_CHILD=1")
	tt.cmd.Stderr = tt.stderr
	stdout, err := tt.cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	tt.stdout = bufio.NewReader(stdout)
	if tt.stdin, err = tt.cmd.StdinPipe(); err != nil {
		t.Fatal(err)
	}
	if err := tt.cmd.Start(); err != nil {
		t.Fatal(err)
	}
	return tt
}

// InputLine writes the given text to the childs stdin.
// This method can also be called from an expect template, e.g.:
//
//     gubiq.expect(`Passphrase: {{.InputLine "password"}}`)
func (tt *testgubiq) InputLine(s string) string {
	io.WriteString(tt.stdin, s+"\n")
	return ""
}

func (tt *testgubiq) setTemplateFunc(name string, fn interface{}) {
	if tt.Func == nil {
		tt.Func = make(map[string]interface{})
	}
	tt.Func[name] = fn
}

// expect runs its argument as a template, then expects the
// child process to output the result of the template within 5s.
//
// If the template starts with a newline, the newline is removed
// before matching.
func (tt *testgubiq) expect(tplsource string) {
	// Generate the expected output by running the template.
	tpl := template.Must(template.New("").Funcs(tt.Func).Parse(tplsource))
	wantbuf := new(bytes.Buffer)
	if err := tpl.Execute(wantbuf, tt); err != nil {
		panic(err)
	}
	// Trim exactly one newline at the beginning. This makes tests look
	// much nicer because all expect strings are at column 0.
	want := bytes.TrimPrefix(wantbuf.Bytes(), []byte("\n"))
	if err := tt.matchExactOutput(want); err != nil {
		tt.Fatal(err)
	}
	tt.Logf("Matched stdout text:\n%s", want)
}

func (tt *testgubiq) matchExactOutput(want []byte) error {
	buf := make([]byte, len(want))
	n := 0
	tt.withKillTimeout(func() { n, _ = io.ReadFull(tt.stdout, buf) })
	buf = buf[:n]
	if n < len(want) || !bytes.Equal(buf, want) {
		// Grab any additional buffered output in case of mismatch
		// because it might help with debugging.
		buf = append(buf, make([]byte, tt.stdout.Buffered())...)
		tt.stdout.Read(buf[n:])
		// Find the mismatch position.
		for i := 0; i < n; i++ {
			if want[i] != buf[i] {
				return fmt.Errorf("Output mismatch at ◊:\n---------------- (stdout text)\n%s◊%s\n---------------- (expected text)\n%s",
					buf[:i], buf[i:n], want)
			}
		}
		if n < len(want) {
			return fmt.Errorf("Not enough output, got until ◊:\n---------------- (stdout text)\n%s\n---------------- (expected text)\n%s◊%s",
				buf, want[:n], want[n:])
		}
	}
	return nil
}

// expectRegexp expects the child process to output text matching the
// given regular expression within 5s.
//
// Note that an arbitrary amount of output may be consumed by the
// regular expression. This usually means that expect cannot be used
// after expectRegexp.
func (tt *testgubiq) expectRegexp(resource string) (*regexp.Regexp, []string) {
	var (
		re      = regexp.MustCompile(resource)
		rtee    = &runeTee{in: tt.stdout}
		matches []int
	)
	tt.withKillTimeout(func() { matches = re.FindReaderSubmatchIndex(rtee) })
	output := rtee.buf.Bytes()
	if matches == nil {
		tt.Fatalf("Output did not match:\n---------------- (stdout text)\n%s\n---------------- (regular expression)\n%s",
			output, resource)
		return re, nil
	}
	tt.Logf("Matched stdout text:\n%s", output)
	var submatch []string
	for i := 0; i < len(matches); i += 2 {
		submatch = append(submatch, string(output[i:i+1]))
	}
	return re, submatch
}

// expectExit expects the child process to exit within 5s without
// printing any additional text on stdout.
func (tt *testgubiq) expectExit() {
	var output []byte
	tt.withKillTimeout(func() {
		output, _ = ioutil.ReadAll(tt.stdout)
	})
	tt.cmd.Wait()
	if tt.removeDatadir {
		os.RemoveAll(tt.Datadir)
	}
	if len(output) > 0 {
		tt.Errorf("Unmatched stdout text:\n%s", output)
	}
}

func (tt *testgubiq) interrupt() {
	tt.cmd.Process.Signal(os.Interrupt)
}

// stderrText returns any stderr output written so far.
// The returned text holds all log lines after expectExit has
// returned.
func (tt *testgubiq) stderrText() string {
	tt.stderr.mu.Lock()
	defer tt.stderr.mu.Unlock()
	return tt.stderr.buf.String()
}

func (tt *testgubiq) withKillTimeout(fn func()) {
	timeout := time.AfterFunc(5*time.Second, func() {
		tt.Log("killing the child process (timeout)")
		tt.cmd.Process.Kill()
		if tt.removeDatadir {
			os.RemoveAll(tt.Datadir)
		}
	})
	defer timeout.Stop()
	fn()
}
=======
	// Boot "geth". This actually runs the test binary but the TestMain
	// function will prevent any tests from running.
	tt.Run("geth-test", args...)
>>>>>>> ab5646c532292b51e319f290afccf6a44f874372:cmd/geth/run_test.go

	return tt
}
