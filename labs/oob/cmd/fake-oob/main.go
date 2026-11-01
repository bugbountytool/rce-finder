package main

import (
	"flag"
	"log"
	"net"
	"net/http"
	"os"

	laboob "github.com/bugbountytool/rce-finder/labs/oob"
)

func main() {
	listen := flag.String("listen", "127.0.0.1:18080", "loopback listener for the local fake OOB API")
	flag.Parse()
	server := laboob.NewStandalone()
	listener, err := net.Listen("tcp", *listen)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("local fake OOB listening on %s", listener.Addr())
	if err := http.Serve(listener, server.Handler()); err != nil {
		log.Print(err)
		os.Exit(1)
	}
}
