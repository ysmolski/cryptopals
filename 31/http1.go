package main

import (
	"cryptopals/util"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"time"
)

var (
	key = []byte("some random key")
)

func insecureSame(a, b []byte) bool {
	for i := 0; i < len(a) && i < len(b); i++ {
		if a[i] != b[i] {
			return false
		}
		time.Sleep(50 * time.Millisecond)
	}
	return true
}

func response(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	fmt.Println(r.URL.Path, q)
	file, ok := q["file"]
	if !ok {
		w.WriteHeader(http.StatusBadRequest)
		io.WriteString(w, "file parameter is missing")
		return
	}
	sign, ok := q["signature"]
	if !ok {
		w.WriteHeader(http.StatusBadRequest)
		io.WriteString(w, "signature parameter is missing")
		return
	}
	// fmt.Println(file[0], sign[0])
	clientSign, err := hex.DecodeString(sign[0])
	if err != nil {
		io.WriteString(w, "sign is not hex encoded!")
		return
	}
	serverSign := util.HMacSha1(key, []byte(file[0]))
	same := insecureSame(clientSign, serverSign)
	if same {
		w.WriteHeader(http.StatusOK)
	} else {
		w.WriteHeader(http.StatusInternalServerError)
	}
	// fmt.Printf("%x %x -> %t\n", clientSign, serverSign, same)
}

func main() {
	http.HandleFunc("/", response)
	http.ListenAndServe(":8000", nil)
}
