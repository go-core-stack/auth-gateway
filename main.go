// Copyright © 2025 Prabhjot Singh Sethi, All Rights reserved
// Author: Prabhjot Singh Sethi <prabhjot.sethi@gmail.com>

package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/Prabhjot-Sethi/core/db"
	"github.com/Prabhjot-Sethi/core/sync"
	"github.com/Prabhjot-Sethi/core/values"

	"github.com/Prabhjot-Sethi/auth-gateway/pkg/config"
	"github.com/Prabhjot-Sethi/auth-gateway/pkg/controller/tenant"
	"github.com/Prabhjot-Sethi/auth-gateway/pkg/keycloak"
	"github.com/Prabhjot-Sethi/auth-gateway/pkg/table"
)

var (
	// path to config file
	configFile string

	// client handle to database store
	client db.StoreClient
)

const (
	// name of the root tenant to be created by default
	rootTenantName = "root"

	// service name this process will be hosting
	serviceName = "auth-gateway"
)

// Parse flags for the process
func parseFlags() {
	// Add String variable flag "-config" allowing option to specify
	// the relevant config file for the process
	flag.StringVar(&configFile, "config", "", "path to the config file")

	// parse the supplied flags
	flag.Parse()
}

func locateRootTenant() {
	// locate the tenant table to work with
	tenantTbl, err := table.LocateTenantTable(client)
	if err != nil {
		log.Panicf("failed to locate Tenant table: %s", err)
	}

	// Root Tenant Key
	tKey := &table.TenantKey{
		Name: rootTenantName,
	}

	// Root Tenant Entry
	tEntry := &table.TenantEntry{
		Config: &table.TenantConfig{
			DispName: "Root Tenant",
			Desc:     "Root Tenant for the system, created by default",
			DefaultAdmin: &table.UserCredentials{
				UserID:   "admin",
				Password: "Password",
			},
			IsRoot: true,
		},
	}

	// Locate the Tenant Entry
	err = tenantTbl.Locate(context.Background(), tKey, tEntry)
	if err != nil {
		log.Panicf("failed to locate root tenant entry: %s", err)
	}
}

func main() {
	// setup a context for the main function allowing cleanup
	ctx, cancelFn := context.WithCancel(context.Background())
	defer func() {
		cancelFn()
		// Allow a buffer time of 10 seconds for processing the closure
		// of the provided context
		time.Sleep(10 * time.Second)
	}()

	// Parse the flag options for the process
	parseFlags()
	conf, err := config.ParseConfig(configFile)
	if err != nil {
		log.Panicf("Failed to parse config: %s", err)
	}
	log.Printf("Got config %s:%s", conf.GetConfigDB().Host, conf.GetConfigDB().Port)

	// Get mongo configdb database Credentials from environment variables
	// this is done to ensure that the credentials are not stored in plain
	// text as part of the config files
	username, password := values.GetMongoConfigDBCredentials()

	// read the configuration for configdb
	config := &db.MongoConfig{
		Host:     conf.GetConfigDB().Host,
		Port:     conf.GetConfigDB().Port,
		Username: username,
		Password: password,
	}

	// create new client for the mongodb config
	client, err = db.NewMongoClient(config)
	if err != nil {
		log.Panicf("Failed to get handle of mongodb client: %s", err)
	}

	// ensure running heath check to validate that provided mongodb endpoint
	// is usable
	err = client.HealthCheck(context.Background())
	if err != nil {
		log.Panicf("failed to perform Health check with DB Error: %s", err)
	}

	// initialize the sync owner table
	err = sync.InitializeOwnerTableDefault(ctx, client, serviceName)
	if err != nil {
		log.Panicf("Failed to initialize owner table using default store: %s", err)
	}

	// ensure that the root tenant exists to work with as the default
	// tenancy
	locateRootTenant()

	// create a new keycloak client
	client, err := keycloak.New("http://localhost:8080")
	if err != nil {
		// failed to create keycloak client, nothing more can be done
		log.Panicf("failed to create keycloak client: %s", err)
	}
	defer func() {
		_ = client.Logout(context.Background())
	}()

	// Create tenant setup controller
	_, err = tenant.NewSetupController(client)
	if err != nil {
		log.Panicf("failed to create tenant setup controller: %s", err)
	}

	// Create tenant Roles controller
	_, err = tenant.NewRoleController(client)
	if err != nil {
		log.Panicf("failed to create tenant roles controller: %s", err)
	}

	// Create tenant Admin controller
	_, err = tenant.NewAdminController(client)
	if err != nil {
		log.Panicf("failed to create tenant admin controller: %s", err)
	}

	log.Println("Initialization of Auth Gateway completed")

	sigc := make(chan os.Signal, 1)
	signal.Notify(sigc,
		syscall.SIGINT,
		syscall.SIGTERM,
		syscall.SIGQUIT)
	s := <-sigc
	log.Printf("Terminating Process got signal: %s", s)
}
