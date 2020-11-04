// Identify authentication and authorization service
//
// Copyright (C) 2020 Alexei Broner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

package test

import (
	"context"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"regexp"
	"testing"
	"time"

	"github.com/Netflix/go-expect"
	"github.com/brianvoe/gofakeit/v5"

	gocli "github.com/akb/go-cli"

	"github.com/akb/identify/internal/cli"
)

func init() {
	gofakeit.Seed(time.Now().UnixNano())
	os.Chdir("../..")
}

var dbPath, tokenDBPath, certPath, certKeyPath string

func TestMain(m *testing.M) {
	dir, err := ioutil.TempDir("", "identify-testing")
	if err != nil {
		panic(err)
	}
	defer os.RemoveAll(dir)

	dbPath = filepath.Join(dir, "identity.db")
	tokenDBPath = filepath.Join(dir, "token.db")
	certPath = filepath.Join(dir, "certificate.pem")
	certKeyPath = filepath.Join(dir, "certificate-key.pem")

	os.Exit(m.Run())
}

type CommandTestResult struct {
	Status int
	STDOUT string
	STDERR string
}

type ErrorNonZeroExit struct {
	status int
}

func (err ErrorNonZeroExit) Error() string {
	return fmt.Sprintf("expected zero exit status; received %d", err.status)
}

func (r *CommandTestResult) String() string {
	return fmt.Sprintf("\n[BEGIN STDOUT]\n%s[END STDOUT]\n\n"+
		"[BEGIN STDERR]\n%s[END STDERR]\n", r.STDOUT, r.STDERR)
}

func RunCommandTest(t *testing.T,
	environment map[string]string,
	arguments []string,
	interact func(*expect.Console, context.CancelFunc),
) *CommandTestResult {
	ctx := context.Background()
	ctx, cancel := context.WithCancel(ctx)

	arguments = append([]string{os.Args[0]}, arguments...)
	system, output := gocli.NewTestSystem(t, arguments, environment)

	done := Async(func() {
		interact(system.Console, cancel)
	})

	status := gocli.Main(ctx, &cli.IdentifyCommand{}, system)

	<-done

	return &CommandTestResult{
		Status: status,
		STDOUT: output.STDOUT.String(),
		STDERR: output.STDERR.String(),
	}
}

func Async(fn func()) chan struct{} {
	done := make(chan struct{})
	go func() {
		fn()
		done <- struct{}{}
	}()
	return done
}

func In(d time.Duration, fn func()) chan struct{} {
	return Async(func() {
		time.Sleep(d)
		fn()
	})
}

func TestCommand(t *testing.T) {
	var output string
	var err error
	result := RunCommandTest(t, map[string]string{}, []string{},
		func(c *expect.Console, cancel context.CancelFunc) {
			done := In(10*time.Millisecond, func() { c.Tty().Close() })

			t.Log("waiting for eof...")
			output, err = c.ExpectEOF()
			t.Log("waiting for tty to close...")
			<-done
		},
	)
	if err != nil {
		t.Fatal(err)
	}

	pattern := regexp.MustCompile(`Usage: identify <subcommand>`)
	if !pattern.Match([]byte(output)) {
		t.Fatalf("error matching command output for \"identify\"\n%s\n", err)
	}

	if result.Status != 0 {
		t.Errorf("Expected status code 0, received %d.\n", result.Status)
	}
}
