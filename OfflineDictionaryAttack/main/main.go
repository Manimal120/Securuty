package main

import (
	"bufio"
	"crypto/sha1"
	"encoding/base64"
	"fmt"
	"os"
	"strings"
)

// Get the possible passwords in the dictionary
func dictionaryRead(fileName string) []string {
	var res []string
	if dictionary, err := os.Open(fileName); err != nil {
		panic(err)
	} else {
		scanner2 := bufio.NewScanner(dictionary)
		//var flag int
		for scanner2.Scan() {
			res = append(res, scanner2.Text())
		}
	}
	return res
}

// Encoding the possible password into "Base64-encoded SHA-1"
func sha1base64Find(dictionarySample string) string {
	// SHA-1
	h := sha1.New()
	h.Write([]byte(dictionarySample))
	sha1Res := h.Sum(nil)

	// Base64-encoded SHA-1
	b64Res := base64.StdEncoding.EncodeToString(sha1Res)

	// Final result
	return "{SHA}" + b64Res
}

func main() {
	dictionaryFilePath := "go_code/Security/password.lst"

	var dictionaryList []string = dictionaryRead(dictionaryFilePath)

	if htpfile, err := os.Open("go_code/Security/htpfile"); err != nil {
		panic(err)
	} else {
		defer htpfile.Close()

		scanner1 := bufio.NewScanner(htpfile)

		var usrName string
		var usrPsd string

		fmt.Println("Opening .htpasswd in the current directory...")

		for scanner1.Scan() {
			var shadow = strings.Split(scanner1.Text(), ":")
			usrName = shadow[0]
			usrPsd = shadow[1]
			fmt.Print("Guessing password for user " + usrName + " ... ")

			var flag bool
			var guessPsd string
			for _, value := range dictionaryList {
				if sha1base64Find(value) == usrPsd {
					flag = true
					guessPsd = value
					break
				}
			}

			if flag {
				fmt.Println("found: " + guessPsd)
			} else {
				fmt.Println("timeout")
			}
		}
	}
}
