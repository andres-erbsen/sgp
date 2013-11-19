package main

import (
	"os"
	"io/ioutil"
	"log"
	"code.google.com/p/goprotobuf/proto"
	"github.com/andres-erbsen/sgp"
)

func main() {
	if len(os.Args) != 2 {
		log.Fatal("USAGE: ", os.Args[0], " NAME < secretkey")
	}
	sk_bytes, err := ioutil.ReadAll(os.Stdin)
	var sk sgp.SecretKey
	err = sk.Parse(sk_bytes)
	if err != nil {
		log.Fatal(err)
	}
	
	attribution := &sgp.Attribution{}
	attribution.Name = []byte(os.Args[1])
	attribution.Pubkey = sk.Entity.Bytes

	atb_bytes, err := proto.Marshal(attribution)
	if err != nil {
		log.Fatal(err)
	}
	
	cert := sk.Sign(atb_bytes)
	log.Print(atb_bytes, sk, sk.Entity)
	if ! sk.Entity.Verify(cert) {
		log.Fatal("Signature verification failed")
	}
	os.Stdout.Write(cert)
}

