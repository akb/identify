package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	"github.com/akb/go-cli"

	"github.com/akb/identify/cmd/config"
	"github.com/akb/identify/internal/identity"
	"github.com/akb/identify/internal/token"
)

type newTokenCommand struct {
	id *string
}

func (newTokenCommand) Help() {
	fmt.Println("identify - authentication and authorization service")
	fmt.Println("")
	fmt.Println("Usage: identify")
	fmt.Println("")
	fmt.Println("Authenticates user and issues a new pair of tokens")
	fmt.Println("")
	fmt.Println("Environment Variables:")
	fmt.Println("")
	fmt.Println("IDENTITY_DB_PATH")
	fmt.Println("- path to identity database file")
	fmt.Println("- default: $HOME/.identify/identity.db")
	fmt.Println("IDENTITY_TOKEN_DB_PATH")
	fmt.Println("- path to token database file")
	fmt.Println("- default: $HOME/.identify/token.db")
	fmt.Println("IDENTITY_TOKEN_SECRET")
	fmt.Println("- secret key used to sign tokens")
}

func (c *newTokenCommand) Flags(f *flag.FlagSet) {
	c.id = f.String("id", "", "identity to authenticate")
}

func (c *newTokenCommand) Command(ctx context.Context) int {
	if len(*c.id) == 0 {
		fmt.Println("an identity must be provided to authenticate")
		return 1
	}

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

	i, err := store.Get(*c.id)
	if err != nil {
		fmt.Println(err.Error())
		return 1
	}

	passphrase, err := promptForPassphrase()
	if err != nil {
		fmt.Println(err.Error())
		return 1
	}

	if !i.Authenticate(passphrase) {
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
		fmt.Printf("An error occurred while opening token database file:\n")
		fmt.Println(err.Error())
		os.Exit(1)
	}
	defer tokenStore.Close()

	access, refresh, err := tokenStore.New(i)
	if err != nil {
		fmt.Printf("An error occurred while generating token:\n")
		fmt.Println(err.Error())
		os.Exit(1)
	}

	fmt.Printf("Access Token: %s\n%s\n", access.ID(), access.String())
	fmt.Println("")
	fmt.Printf("Refresh Token: %s\n%s\n", refresh.ID(), refresh.String())
	return 0
}

func (newTokenCommand) Subcommands() cli.CLI {
	return nil
}
