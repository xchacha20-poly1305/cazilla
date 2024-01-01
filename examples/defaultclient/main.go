package main

import (
	"log"
	"net/http"

	"github.com/xchacha20-poly1305/cazilla"
)

func main() {
	// apply cazilla shared CA pool to http.DefaultTransport,
	// which is used by http.DefaultClient.
	// if you are using custom http client, use cazilla.ConfigureHTTPTransport or configure it by yourself.
	cazilla.ConfigureDefault()

	req, _ := http.NewRequest(http.MethodGet, "https://gstatic.com/generate_204", nil)
	response, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Panic("error when requesting", err)
	}
	response.Body.Close()

	if response.StatusCode == 204 {
		log.Println("successfully requested google! response code", response.StatusCode)
	} else {
		log.Panic("request failed! response code", response.StatusCode)
	}
}
