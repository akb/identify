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

var dbPath string

func TestMain(m *testing.M) {
	dir, err := ioutil.TempDir("", "identify-testing")
	if err != nil {
		panic(err)
	}
	defer os.RemoveAll(dir)

	dbPath = filepath.Join(dir, "identity.db")

	os.Exit(m.Run())
}

type CommandTestResult struct {
	Status int
	STDOUT string
	STDERR string
}

func (r *CommandTestResult) String() string {
	return fmt.Sprintf("[BEGIN STDOUT]\n%s[END STDOUT]\n\n"+
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
