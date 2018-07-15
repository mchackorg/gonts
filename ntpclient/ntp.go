package main

import (
	"fmt"

	"github.com/beevik/ntp"
)

type Data struct {
	C2s_key string
	S2c_key string
	Server  []string
	Cookie  [][]byte
	Algo    uint16 // AEAD
}

const datafn = "../ke.json"

func main() {
	// data := new(Data)
	// f, _ := ioutil.ReadFile(datafn)
	// json.Unmarshal(f, &data)
	// fmt.Printf("%s\n", data.C2s_key)

	ntpTime, err := ntp.Time("localhost")
	if err != nil {
		fmt.Println(err)
	}

	fmt.Printf("Network time: %vx\n", ntpTime)
}
