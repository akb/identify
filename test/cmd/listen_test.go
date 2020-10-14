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
	"strings"
	"testing"
	"time"

	"github.com/Netflix/go-expect"
)

func TestListenCommand(t *testing.T) {
	ti, err := GenerateNewIdentity(t)
	if err != nil {
		t.Fatal(err)
	}

	err = GenerateCertificate(t, ti)
	if err != nil {
		t.Fatal(err)
	}

	environment := map[string]string{
		"IDENTIFY_DB_PATH":              dbPath,
		"IDENTIFY_TOKEN_DB_PATH":        tokenDBPath,
		"IDENTIFY_CERTIFICATE_PATH":     certPath,
		"IDENTIFY_CERTIFICATE_KEY_PATH": certKeyPath,
	}

	arguments := []string{"listen", fmt.Sprintf("-id=%s", ti.ID)}

	var output string
	t.Logf("running '%s'", strings.Join(arguments, " "))
	result := RunCommandTest(t, environment, arguments,
		func(c *expect.Console, cancel context.CancelFunc) {
			t.Log("waiting for passphrase prompt...")
			_, err = c.Expectf("Passphrase: ")
			if err != nil {
				return
			}

			t.Logf("sending passphrase %s", ti.Passphrase)
			_, err = c.SendLine(ti.Passphrase)
			if err != nil {
				return
			}

			done := In(100*time.Millisecond, func() {
				c.Tty().Close()
				cancel()
			})

			t.Log("waiting for eof...")
			output, err = c.ExpectEOF()
			<-done
		},
	)
	if err != nil {
		t.Fatal(err)
	}

	if result.Status != 0 {
		t.Errorf("error: '%s' returned nonzero status %d", strings.Join(arguments, " "), result.Status)
		t.Fatal(result.String())
	}

	if strings.TrimSpace(output) != "Listening for HTTP requests on 0.0.0.0:8443..." {
		t.Fatalf("unexpected output: '%s'\n", output)
		t.Fatal(result.String())
	}
}
