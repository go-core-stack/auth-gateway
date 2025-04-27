package main

import (
	"flag"
	"log"

	"github.com/Prabhjot-Sethi/auth-gateway/pkg/config"
)

var (
	configFile string
)

func parseFlags() {
	// Add String variable flag "-config" allowing option to specify
	// the relevant config file for the process
	flag.StringVar(&configFile, "config", "", "path to the config file")

	flag.Parse()
}

func main() {
	parseFlags()
	conf, err := config.ParseConfig(configFile)
	if err != nil {
		log.Panicf("Failed to parse config: %s", err)
	}
	log.Printf("Got config %s:%d", conf.GetConfigDB().Host, conf.GetConfigDB().Port)
}
