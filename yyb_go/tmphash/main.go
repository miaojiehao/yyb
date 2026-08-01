package main

import (
	"fmt"

	"yyb_go/internal/auth"
)

func main() {
	h, err := auth.HashPassword("6076599")
	if err != nil {
		panic(err)
	}
	fmt.Println(h)
}
