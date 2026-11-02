package main

import (
 "net/http"

 "github.com/bugbountytool/rce-finder/labs/apps/apilab"
)

func main() {
 _ = http.ListenAndServe("127.0.0.1:0", apilab.Handler())
}
