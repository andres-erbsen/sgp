package main

import (
	"log"
	"os"
	"time"
	"crypto/rand"
	"github.com/andres-erbsen/sgp"
)

func main() {
	t := time.Now()
	pk, sk, err := sgp.GenerateKey(rand.Reader, t)
	if err != nil {
		log.Fatal(err)
	}
	os.Stdout.Write(pk.Bytes)
	os.Stderr.Write(sk.Serialize())
}
