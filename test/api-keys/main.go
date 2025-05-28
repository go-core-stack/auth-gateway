// Copyright © 2025 Prabhjot Singh Sethi, All Rights reserved
// Author: Prabhjot Singh Sethi <prabhjot.sethi@gmail.com>

package main

import (
	"io"
	"log"
	"net/http"
	"os"

	"github.com/go-core-stack/auth/hash"
)

func getApiKeyId() string {
	val, found := os.LookupEnv("ApiKeyID")
	if !found {
		return ""
	}
	return val
}

func getApiKeySecret() string {
	val, found := os.LookupEnv("ApiKeySecret")
	if !found {
		return ""
	}
	return val
}

func main() {
	generator := hash.NewGenerator(getApiKeyId(), getApiKeySecret())
	r, _ := http.NewRequest(http.MethodGet, "http://localhost:8090/api/auth/v1/tenant/root/users", nil)
	generator.AddAuthHeaders(r)
	client := &http.Client{}
	func() {
		resp, err := client.Do(r)
		if err != nil {
			log.Printf("got error performing http req: %s", err)
			return
		}
		defer func() {
			_ = resp.Body.Close()
		}()
		bodyBytes, _ := io.ReadAll(resp.Body)
		log.Printf("resp: %s", string(bodyBytes))
	}()

	r, _ = http.NewRequest(http.MethodGet, "http://localhost:8090/api/myaccount/v1/info", nil)
	generator.AddAuthHeaders(r)
	func() {
		resp, err := client.Do(r)
		if err != nil {
			log.Printf("got error performing http req: %s", err)
			return
		}
		defer func() {
			_ = resp.Body.Close()
		}()
		bodyBytes, _ := io.ReadAll(resp.Body)
		log.Printf("resp: %s", string(bodyBytes))
	}()
}
