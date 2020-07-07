package main

import (
	"context"
	"flag"
	"fmt"

	"github.com/akb/go-cli"
)

type deleteCommand struct{}

func (deleteCommand) Help() {
	fmt.Println("identify - authentication and authorization service")
	fmt.Println("")
	fmt.Println("Usage: identify delete <resource> <id>")
	fmt.Println("")
	fmt.Println("Delete resources.")
}

func (deleteCommand) Flags(f *flag.FlagSet) {}

func (c deleteCommand) Command(ctx context.Context) int {
	c.Help()
	return 0
}

func (deleteCommand) Subcommands() cli.CLI {
	return cli.CLI{
		"token": &deleteTokenCommand{},
	}
}
