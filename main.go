package main

import (
	"context"
	"flag"
	"log"
	"time"

	"github.com/Prabhjot-Sethi/core/db"
	"github.com/Prabhjot-Sethi/core/values"

	"github.com/Prabhjot-Sethi/auth-gateway/pkg/config"
	"github.com/Prabhjot-Sethi/auth-gateway/pkg/table"
)

var (
	// path to config file
	configFile string

	// client handle to database store
	client db.StoreClient
)

const (
	RootTenantName = "root"
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
		Name: RootTenantName,
	}

	// Root Tenant Entry
	tEntry := &table.TenantEntry{
		Desc: "Root Tenant for the system, created by default",
	}

	// Locate the Tenant Entry
	err = tenantTbl.Locate(context.Background(), tKey, tEntry)
	if err != nil {
		log.Panicf("failed to locate root tenant entry: %s", err)
	}
}

func main() {
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

	// ensure that the root tenant exists to work with as the default
	// tenancy
	locateRootTenant()

	log.Println("Initialization of Auth Gateway completed")
	// TODO(prabhjot) enter in endless loop to keep the microservice running
	// later on this will be handled differently as part of the server hosting
	for {
		time.Sleep(5 * time.Second)
	}
}
