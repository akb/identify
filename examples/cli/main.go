package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

var token string

func init() {
	token = os.Getenv("TOKEN")
}

func main() {
	fmt.Printf("Token: %s\n", token)

	reader := bufio.NewReader(os.Stdin)

	fmt.Print("Enter a string to reverse: ")
	text, _ := reader.ReadString('\n')
	text = strings.Replace(text, "\n", "", -1)

	fmt.Println(reverse(text))
}

func reverse(s string) string {
	runes := []rune(s)
	for i, j := 0, len(runes)-1; i < j; i, j = i+1, j-1 {
		runes[i], runes[j] = runes[j], runes[i]
	}
	return string(runes)
}
