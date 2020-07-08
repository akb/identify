package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"

	"github.com/akb/go-cli"

	"github.com/akb/identify/cmd/config"
	"github.com/akb/identify/internal/identity"
	"github.com/akb/identify/internal/token"
)

type Credentials struct {
	Access  string `json:"access"`
	Refresh string `json:"refresh"`
}

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
	fmt.Println("IDENTIFY_DB_PATH")
	fmt.Println("- path to identity database file")
	fmt.Println("- default: $HOME/.identify/identity.db")
	fmt.Println("")
	fmt.Println("IDENTIFY_CREDENTIALS_PATH")
	fmt.Println("- path to save credentials file as")
	fmt.Println("- default: $HOME/.identify/credentials.json")
	fmt.Println("")
	fmt.Println("IDENTIFY_TOKEN_DB_PATH")
	fmt.Println("- path to token database file")
	fmt.Println("- default: $HOME/.identify/token.db")
	fmt.Println("")
	fmt.Println("IDENTIFY_TOKEN_SECRET")
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

	credsPath, err := config.GetCredentialsPath()
	if err != nil {
		fmt.Println(err.Error())
		return 1
	}

	dbPath, err := config.GetDBPath()
	if err != nil {
		fmt.Println(err.Error())
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

	store, err := identity.NewLocalStore(dbPath)
	if err != nil {
		fmt.Println(err.Error())
		return 1
	}
	defer store.Close()

	tokenStore, err := token.NewLocalStore(tokenDBPath, tokenSecret)
	if err != nil {
		fmt.Println(err.Error())
		return 1
	}
	defer tokenStore.Close()

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

	access, refresh, err := tokenStore.New(i)
	if err != nil {
		fmt.Println(err.Error())
		return 1
	}

	creds := Credentials{access.String(), refresh.String()}
	credsJSON, err := json.MarshalIndent(creds, "", "  ")
	if err != nil {
		fmt.Println(err.Error())
		return 1
	}

	if err = ioutil.WriteFile(credsPath, credsJSON, 0600); err != nil {
		fmt.Println(err.Error())
		return 1
	}

	fmt.Println("Authentication succeeded.")
	return 0
}

func (newTokenCommand) Subcommands() cli.CLI {
	return nil
}
