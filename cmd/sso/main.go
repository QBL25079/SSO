package main

import (
	"fmt"

	"github.com/QBL25079/SSO/internal/config"
)

func main() {
	cfg := config.MustLoad()

	fmt.Println(cfg)
}
