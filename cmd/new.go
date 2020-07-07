package main

import (
	"context"
	"flag"
	"fmt"

	"github.com/akb/go-cli"
)

type newCommand struct{}

func (newCommand) Help() {
	fmt.Println("identify - authentication and authorization service")
	fmt.Println("")
	fmt.Println("Usage: identify new <resource>")
	fmt.Println("")
	fmt.Println("Create new resources.")
}

func (newCommand) Flags(f *flag.FlagSet) {}

func (c newCommand) Command(ctx context.Context) int {
	c.Help()
	return 0
}

func (newCommand) Subcommands() cli.CLI {
	return cli.CLI{
		"identity": &newIdentityCommand{},
		"token":    &newTokenCommand{},
	}
}
