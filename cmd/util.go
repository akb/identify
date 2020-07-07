package main

import (
	"fmt"
	"syscall"

	"golang.org/x/crypto/ssh/terminal"
)

func promptForPassphrase() (string, error) {
	fmt.Print("Enter passphrase: ")
	passphrase, err := terminal.ReadPassword(int(syscall.Stdin))
	fmt.Println("")
	if err != nil {
		fmt.Printf("Error while reading passphrase.\n%s\n", err.Error())
		return "", err
	}
	return string(passphrase), nil
}
