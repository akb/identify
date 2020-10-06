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

var dbPath string

func init() {
	gofakeit.Seed(time.Now().UnixNano())
}

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
	StatusCode int
}

func RunCommandTest(t *testing.T,
	environment map[string]string,
	arguments []string,
	interact func(*expect.Console),
) int {
	system := gocli.NewTestSystem(t, arguments, environment)

	done := make(chan struct{})
	go func() {
		interact(system.Console)
		done <- struct{}{}
	}()

	arguments = append([]string{os.Args[0]}, arguments...)
	status := gocli.Main(&cli.IdentifyCommand{}, system)
	<-done
	return status
}

//func (c *CommandTest) Close() {
//	c.Console.Tty().Close()
//	c.Console.Close()
//}

//func (c CommandTest) Authenticate(passphrase string) error {
//	var err error
//	_, err = c.Expectf("Passphrase: ")
//	if err != nil {
//		return err
//	}
//
//	_, err = c.SendLine(passphrase)
//	if err != nil {
//		return err
//	}
//
//	return nil
//}

//func (c *CommandTest) GetOutput() (string, error) {
//	output, err := c.ExpectEOF()
//	if err != nil {
//		return "", err
//	}
//
//	trimmed := strings.TrimSpace(output)
//
//	c.Output = trimmed
//
//	return trimmed, nil
//}
