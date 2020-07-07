package main

import (
	"context"
	"flag"
	"fmt"

	"github.com/akb/go-cli"

	"github.com/akb/identify/cmd/config"
	"github.com/akb/identify/internal/identity"
	"github.com/akb/identify/internal/token"
)

type deleteTokenCommand struct {
	id      *string
	tokenID *string
}

func (deleteTokenCommand) Help() {
	fmt.Println("identify - authentication and authorization service")
	fmt.Println("")
	fmt.Println("Usage: identify delete token <id>")
	fmt.Println("")
	fmt.Println("Delete a token. Authorization may be required.")
}

func (c *deleteTokenCommand) Flags(f *flag.FlagSet) {
	c.id = f.String("id", "", "identity to authenticate")
	c.tokenID = f.String("token-id", "", "id of token to delete")
}

func (c deleteTokenCommand) Command(ctx context.Context) int {
	if len(*c.id) == 0 {
		fmt.Println("an identity must be provided to authenticate")
		return 1
	}

	dbPath, err := config.GetDBPath()
	if err != nil {
		fmt.Println(err)
		return 1
	}

	store, err := identity.NewLocalStore(dbPath)
	if err != nil {
		fmt.Println(err)
		return 1
	}

	passphrase, err := promptForPassphrase()
	if err != nil {
		fmt.Println(err)
		return 1
	}

	identity, err := store.Get(*c.id)
	if err != nil {
		fmt.Println(err)
		return 1
	}

	if !identity.Authenticate(passphrase) {
		fmt.Println("unable to authenticate")
		return 1
	}

	tokenSecret, err := config.GetTokenSecret()
	if err != nil {
		fmt.Println(err.Error())
		return 1
	}

	tokenDBPath, err := config.GetTokenDBPath()
	if err != nil {
		fmt.Println(err.Error())
		return 1
	}

	tokenStore, err := token.NewLocalStore(tokenDBPath, tokenSecret)
	if err != nil {
		fmt.Println("An error occurred while opening token database file:")
		fmt.Println(err.Error())
		return 1
	}
	defer tokenStore.Close()

	if err := tokenStore.Delete(identity.String(), *c.tokenID); err != nil {
		fmt.Println("An error occurred while deleting token:")
		fmt.Println(err.Error())
		return 1
	}

	fmt.Println("Token successfully deleted")
	return 0
}

func (deleteTokenCommand) Subcommands() cli.CLI {
	return cli.CLI{
		"token": &deleteTokenCommand{},
	}
}
