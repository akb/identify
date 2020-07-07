package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/akb/go-cli"

	"github.com/akb/identify/cmd/config"
	"github.com/akb/identify/internal/http"
	"github.com/akb/identify/internal/identity"
	"github.com/akb/identify/internal/token"
)

type listenCommand struct{}

func (listenCommand) Help() {
	fmt.Println("identify - authentication and authorization service")
	fmt.Println("")
	fmt.Println("Usage: identify new <resource>")
	fmt.Println("")
	fmt.Println("Create new resources.")
}

func (listenCommand) Flags(f *flag.FlagSet) {}

func (c listenCommand) Command(ctx context.Context) int {
	address := config.GetHTTPAddress()
	realm := config.GetRealm()

	tokenSecret, err := config.GetTokenSecret()
	if err != nil {
		fmt.Println(err.Error())
		return 1
	}

	dbPath, err := config.GetDBPath()
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
		fmt.Printf("An error occurred while opening identity database file:\n")
		fmt.Println(err.Error())
		os.Exit(1)
	}
	defer store.Close()

	tokenStore, err := token.NewLocalStore(tokenDBPath, tokenSecret)
	if err != nil {
		fmt.Printf("An error occurred while opening token database file:\n")
		fmt.Println(err.Error())
		os.Exit(1)
	}
	defer tokenStore.Close()

	server := http.NewServer(
		http.ServerConfig{address, realm, store, tokenStore})

	fmt.Printf("Identity API listening for HTTP requests on %s...\n", address)
	log.Fatal(server.ListenAndServe())
	return 0
}

func (listenCommand) Subcommands() cli.CLI {
	return nil
}
