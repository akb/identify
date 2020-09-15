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
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/brianvoe/gofakeit/v5"
)

var commandName string
var dbPath string

func init() {
	commandName = os.Getenv("IDENTIFY_COMMAND")
	if len(commandName) == 0 {
		commandName = "../bin/identify"
	}
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
