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

func GenerateCertificate(t *testing.T, ti *TestIdentity) error {
	environment := map[string]string{
		"IDENTIFY_DB_PATH":              dbPath,
		"IDENTIFY_CERTIFICATE_PATH":     certPath,
		"IDENTIFY_CERTIFICATE_KEY_PATH": certKeyPath,
	}

	arguments := []string{"new", "certificate", fmt.Sprintf("-id=%s", ti.ID)}

	var err error
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

			done := In(10*time.Millisecond, func() {
				c.Tty().Close()
			})

			t.Log("waiting for eof...")
			_, err = c.ExpectEOF()
			t.Log("waiting for tty to close...", err)
			<-done
		},
	)

	if result.Status != 0 {
		return ErrorNonZeroExit{result.Status}
	}

	return err
}
