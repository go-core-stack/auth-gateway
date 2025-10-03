// Copyright © 2025 Prabhjot Singh Sethi, All Rights reserved
// Author: Prabhjot Singh Sethi <prabhjot.sethi@gmail.com>

package config

import (
	"os"

	"gopkg.in/yaml.v2"
)

// mongo db config struct
type MongoDB struct {
	Uri string `yaml:"uri,omitempty"`
}

type Swagger struct {
	Dir string `yaml:"dir,omitempty"`
}

type Keycloak struct {
	Endpoint string `yaml:"endpoint,omitempty"`
}

type LocationService struct {
	Host string `yaml:"host,omitempty"`
	Port string `yaml:"port,omitempty"`
}

type CorsConfig struct {
	Enabled bool `yaml:"enabled,omitempty"`
}

// Base config struct
type BaseConfig struct {
	ConfigDB        *MongoDB         `yaml:"configDB,omitempty"`
	Swagger         Swagger          `yaml:"swagger,omitempty"`
	Keycloak        *Keycloak        `yaml:"keycloak,omitempty"`
	LocationService *LocationService `yaml:"locationService,omitempty"`
	Cors            CorsConfig       `yaml:"cors,omitempty"`
}

// get Config database information, if the struct
// is nil it ensures sending the default mongodb
// config for base development scenarios
func (c *BaseConfig) GetConfigDB() *MongoDB {
	if c.ConfigDB != nil {
		return c.ConfigDB
	}

	return &MongoDB{
		Uri: "",
	}
}

func (c *BaseConfig) GetKeycloakEndpoint() string {
	if c.Keycloak != nil && c.Keycloak.Endpoint != "" {
		return c.Keycloak.Endpoint
	}

	return "http://localhost:8080"
}

func (c *BaseConfig) GetSwaggerDir() string {
	if c.Swagger.Dir != "" {
		return c.Swagger.Dir
	}

	_, err := os.Stat("/opt/swagger/apidocs/swagger.json")
	if err == nil {
		return "/opt/swagger"
	}

	return "./swagger"
}

func (c *BaseConfig) IsCORSEnabled() bool {
	return c.Cors.Enabled
}

// IsLocationServiceConfigured checks if location service is properly configured
// with both host and port values
func (c *BaseConfig) IsLocationServiceConfigured() bool {
	return c.LocationService != nil &&
		c.LocationService.Host != "" &&
		c.LocationService.Port != ""
}

// GetLocationServiceHost returns the configured location service host
func (c *BaseConfig) GetLocationServiceHost() string {
	if c.LocationService != nil {
		return c.LocationService.Host
	}
	return ""
}

// GetLocationServicePort returns the configured location service port
func (c *BaseConfig) GetLocationServicePort() string {
	if c.LocationService != nil {
		return c.LocationService.Port
	}
	return ""
}

// Parse YAML Config file from the provided config file path
// returns pointer to config structure and error if failed to
// generate the config struct.
// This also ensures handling scenarios when no config file
// is provided
func ParseConfig(filePath string) (*BaseConfig, error) {
	config := &BaseConfig{}
	// Process config file if file path is provided
	if filePath != "" {
		// open the provided config file
		file, err := os.Open(filePath)
		if err != nil {
			return nil, err
		}
		// ensure that we close the file before returning from
		// here, following constructs of release the unused
		// resources for garbage collector to kick in
		defer func() {
			_ = file.Close()
		}()

		// Get a new Yaml decoder
		decoder := yaml.NewDecoder(file)
		// decode the provided yaml config from the config file
		if err := decoder.Decode(config); err != nil {
			return nil, err
		}
	}

	return config, nil
}
