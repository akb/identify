package test

import (
	"os"
)

var commandName string

func init() {
	commandName = os.Getenv("IDENTIFY_COMMAND")
}
