// Copyright © 2025 Prabhjot Singh Sethi, All Rights reserved
// Author: Prabhjot Singh Sethi <prabhjot.sethi@gmail.com>

package main

import (
	"fmt"
	"log"
	"os"
	"time"

	"github.com/go-core-stack/auth-gateway/pkg/keycloak"
)

func getEndpoint() string {
	val, found := os.LookupEnv("KEYCLOAK_ENDPOINT")
	if !found {
		return "http://localhost:8080"
	}
	return val
}

func getUsername() string {
	val, found := os.LookupEnv("Username")
	if !found {
		return "admin"
	}
	return val
}

func getPassword() string {
	val, found := os.LookupEnv("Password")
	if !found {
		return "password"
	}
	return val
}

func getRealm() string {
	val, found := os.LookupEnv("Realm")
	if !found {
		return "root"
	}
	return val
}

func main() {
	client, err := keycloak.NewUserClient(getEndpoint(), getRealm(), getUsername(), getPassword(), true)
	if err != nil {
		log.Panicf("failed to get keycloak client: %s", err)
	}

	t, _ := client.GetAccessToken()
	ticker := time.NewTicker(10 * time.Second)
	fmt.Printf("Access token: %s\n", t)

	for {
		<-ticker.C
		nt, _ := client.GetAccessToken()
		if t != nt {
			t = nt
			fmt.Printf("\nAccess token: %s\n", t)
		}
	}
}
