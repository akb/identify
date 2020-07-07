package main

import (
	"context"
	"flag"
	"fmt"

	"github.com/akb/go-cli"

	"github.com/akb/identify/cmd/config"
	"github.com/akb/identify/internal/identity"
)

type newIdentityCommand struct{}

func (newIdentityCommand) Help() {}

func (c *newIdentityCommand) Flags(f *flag.FlagSet) {
}

func (newIdentityCommand) Command(ctx context.Context) int {
	dbPath, err := config.GetDBPath()
	if err != nil {
		fmt.Println(err.Error())
		return 1
	}

	store, err := identity.NewLocalStore(dbPath)
	if err != nil {
		fmt.Printf("An error occurred while opening identity database file:\n")
		fmt.Println(err.Error())
		return 1
	}
	defer store.Close()

	passphrase, err := promptForPassphrase()
	if err != nil {
		fmt.Printf("Error while reading passphrase.\n%s\n", err.Error())
		return 1
	}

	id, err := store.New(string(passphrase))
	if err != nil {
		fmt.Printf("Error while creating new identity.\n%s\n", err.Error())
		return 1
	}

	fmt.Printf("New identity created: %s\n", id)
	return 0
}

func (newIdentityCommand) Subcommands() cli.CLI {
	return nil
}
