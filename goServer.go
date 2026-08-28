package main

import (
	"fmt"
	"log"
	"net/http"
)	

func handler(w http.ResponseWriter, r *http.Request) {
    fmt.Fprintf(w, "Hello from my tiny go server!\n\n")
    fmt.Fprintf(w, "Method: %s\n", r.Method)
    fmt.Fprintf(w, "Path: %s\n\n", r.URL.Path)

    fmt.Fprintf(w, "Query Parameters:\n")
    fmt.Fprintf(w, "Name: %s\n", r.URL.Query().Get("name"))
    fmt.Fprintf(w, "Age: %s\n", r.URL.Query().Get("age"))
}

func main() {
    http.HandleFunc("/hello", handler)

    log.Fatal(http.ListenAndServe(":8080", nil))
}