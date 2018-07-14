package main

import (
	"fmt"

	"github.com/beevik/ntp"
)

func main() {
	ntpTime, err := ntp.Time("localhost")
	if err != nil {
		fmt.Println(err)
	}

	fmt.Printf("Network time: %vx\n", ntpTime)
}
