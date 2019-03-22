package main

import (
	"fmt"
	"os"
	"strings"

	pwned "github.com/ecnepsnai/go-pwnedpassword"
)

func main() {

	// get password
	pass := os.Args[1:]
	if len(pass) == 0 {
		fmt.Println("usage go pwned.go [password]")
	} else {
		password := strings.Join(pass, "")
		result, err := pwned.IsPwned(password)
		if err != nil {
			// Something went wrong (probably couldn't contact the pwned password API)
		}
		if !result.Pwned {
			// Password hasn't been seen before. Doesn't mean it's safe, just lucky.
		} else {
			count := result.TimesObserved
			fmt.Println("you password has been compromised and has been seen : ", count, "times")
			// Password has been seen `count` times before.
		}

	}

}
