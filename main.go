package main

import (
	"context"
	"flag"
	"log"

	"github.com/Prabhjot-Sethi/core/db"
	"github.com/Prabhjot-Sethi/core/values"

	"github.com/Prabhjot-Sethi/auth-gateway/pkg/config"
	"github.com/Prabhjot-Sethi/auth-gateway/pkg/table"
)

var (
	configFile string
)

// Parse flags for the process
func parseFlags() {
	// Add String variable flag "-config" allowing option to specify
	// the relevant config file for the process
	flag.StringVar(&configFile, "config", "", "path to the config file")

	flag.Parse()
}

func main() {
	// Parse the flag options for the process
	parseFlags()
	conf, err := config.ParseConfig(configFile)
	if err != nil {
		log.Panicf("Failed to parse config: %s", err)
	}
	log.Printf("Got config %s:%s", conf.GetConfigDB().Host, conf.GetConfigDB().Port)

	username, password := values.GetMongoConfigDBCredentials()
	config := &db.MongoConfig{
		Host:     conf.GetConfigDB().Host,
		Port:     conf.GetConfigDB().Port,
		Username: username,
		Password: password,
	}
	client, err := db.NewMongoClient(config)
	if err != nil {
		log.Panicf("Failed to get handle of mongodb client: %s", err)
	}

	err = client.HealthCheck(context.Background())
	if err != nil {
		log.Panicf("failed to perform Health check with DB Error: %s", err)
	}

	tenantTbl, err := table.LocateTenantTable(client)
	if err != nil {
		log.Panicf("failed to locate Tenant table: %s", err)
	}

	tKey := &table.TenantKey{
		Name: "root",
	}

	tEntry := &table.TenantEntry{
		Desc: "Root Tenant for the system, created by default",
	}
	err = tenantTbl.Insert(context.Background(), tKey, tEntry)
	if err != nil {
		log.Panicf("failed to locate root tenant entry: %s", err)
	}
}
