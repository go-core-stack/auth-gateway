// Copyright © 2025 Prabhjot Singh Sethi, All Rights reserved
// Author: Prabhjot Singh Sethi <prabhjot.sethi@gmail.com>

package main

import (
	"context"
	"flag"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	grpc_auth "github.com/grpc-ecosystem/go-grpc-middleware/v2/interceptors/auth"
	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	common "github.com/go-core-stack/auth/context"
	"github.com/go-core-stack/auth/route"
	"github.com/go-core-stack/core/db"
	"github.com/go-core-stack/core/errors"
	"github.com/go-core-stack/core/sync"
	"github.com/go-core-stack/core/values"

	"github.com/go-core-stack/auth-gateway/pkg/apidocs"
	"github.com/go-core-stack/auth-gateway/pkg/auth"
	"github.com/go-core-stack/auth-gateway/pkg/config"
	"github.com/go-core-stack/auth-gateway/pkg/controller/request"
	"github.com/go-core-stack/auth-gateway/pkg/controller/roledef"
	"github.com/go-core-stack/auth-gateway/pkg/controller/tenant"
	"github.com/go-core-stack/auth-gateway/pkg/controller/user"
	"github.com/go-core-stack/auth-gateway/pkg/gateway"
	"github.com/go-core-stack/auth-gateway/pkg/keycloak"
	"github.com/go-core-stack/auth-gateway/pkg/model"
	"github.com/go-core-stack/auth-gateway/pkg/server"
	"github.com/go-core-stack/auth-gateway/pkg/table"
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

var (
	// Port serving Auth Gateway
	GatewayPort = ":8080"

	// TLS Port serving Auth Gateway
	TLSGatewayPort = ":8443"

	// API Port for the server
	APIPort = ":8085"

	APIEndpoint = "http://localhost" + APIPort

	// GRPC Port for the server
	GrpcPort = ":8090"
)

func evaluatePorts() {
	port, ok := os.LookupEnv("API_PORT")
	if ok {
		APIPort = ":" + port
		APIEndpoint = "http://localhost" + APIPort
	}

	port, ok = os.LookupEnv("GATEWAY_PORT")
	if ok {
		GatewayPort = ":" + port
	}

	port, ok = os.LookupEnv("TLS_GATEWAY_PORT")
	if ok {
		TLSGatewayPort = ":" + port
	}

	port, ok = os.LookupEnv("GRPC_PORT")
	if ok {
		GrpcPort = ":" + port
	}
}

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

	// get user table
	userTbl, err := table.GetUserTable()
	if err != nil {
		log.Panicf("failed to get user table: %s", err)
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
				Password: "password",
			},
			IsRoot: true,
		},
	}

	// Locate the Tenant Entry
	err = tenantTbl.Locate(context.Background(), tKey, tEntry)
	if err != nil {
		log.Panicf("failed to locate root tenant entry: %s", err)
	}

	now := time.Now().Unix()
	uEntry := &table.UserEntry{
		Key: &table.UserKey{
			Tenant:   rootTenantName,
			Username: tEntry.Config.DefaultAdmin.UserID,
		},
		Created: now,
		Updated: now,
		Info: &table.UserInfo{
			Email: "test@example.com",
		},
		Password: &table.UserTempPassword{
			Value: tEntry.Config.DefaultAdmin.Password,
		},
	}

	_, err = userTbl.Find(context.Background(), uEntry.Key)
	if err != nil {
		if !errors.IsNotFound(err) {
			log.Panicf("failed to find root tenant user entry: %s", err)
		}
		// User not found, insert the user entry
		err = userTbl.Locate(context.Background(), uEntry.Key, uEntry)
		if err != nil {
			log.Panicf("failed to locate root tenant user entry: %s", err)
		}
	}
}

func createGRPCServerContext() *model.GrpcServerContext {
	var opts = []grpc.ServerOption{}
	// Ensure adding an interceptor to process the auth Headers
	// Validating its existence in common place and storing its
	// processed value in the context
	opts = append(opts, grpc.StreamInterceptor(grpc_auth.StreamServerInterceptor(common.ProcessAuthInfo)))
	opts = append(opts, grpc.UnaryInterceptor(grpc_auth.UnaryServerInterceptor(common.ProcessAuthInfo)))
	serverCtx := &model.GrpcServerContext{
		Server: grpc.NewServer(opts...),
	}

	// Create a server mux with incoming header matcher ensuring,
	// processing of custom headers
	serverCtx.Mux = runtime.NewServeMux(runtime.WithIncomingHeaderMatcher(func(key string) (string, bool) {
		if key == common.HttpClientAuthContext {
			return common.GrpcClientAuthContext, true
		}
		return key, false
	}))

	var err error
	serverCtx.Conn, err = grpc.NewClient(GrpcPort,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		log.Panicf("failed to get grpc client handle: %s", err)
	}

	return serverCtx
}

func startServerContext(serverCtx *model.GrpcServerContext) {
	go func() {
		lis, err := net.Listen("tcp", GrpcPort)
		if err != nil {
			log.Panicf("failed to start GRPC Server")
		}
		log.Panic(serverCtx.Server.Serve(lis))
	}()

	go func() {
		lis, err := net.Listen("tcp", APIPort)
		if err != nil {
			log.Panicf("failed to start GRPC Gateway Server: %s", err)
		}
		log.Panic(http.Serve(lis, serverCtx.Mux))
	}()

	go func() {
		gw := gateway.New()
		oa := apidocs.NewApiDocsServer()
		gwHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.HasPrefix(r.URL.Path, "/apidocs/") {
				oa.ServeHTTP(w, r)
			} else {
				// all APIs are handled via GRPC gateway
				gw.ServeHTTP(w, r)
			}
		})
		go func() {
			lis, err := net.Listen("tcp", GatewayPort)
			if err != nil {
				log.Panicf("failed to start Auth Gateway Server: %s", err)
			}
			log.Panic(http.Serve(lis, gwHandler))
		}()
		lis, err := net.Listen("tcp", TLSGatewayPort)
		if err != nil {
			log.Panicf("failed to start Auth Gateway Server: %s", err)
		}
		log.Panic(http.ServeTLS(lis, gwHandler, "/opt/certs/tls.crt", "/opt/certs/tls.key"))
	}()
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

	// evaluate ports to be used from ENV variables
	// if override ports are provided
	evaluatePorts()

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

	// create the required tables backed by database store

	// locate the tenant table
	_, err = table.LocateTenantTable(client)
	if err != nil {
		log.Panicf("failed to locate Tenant table: %s", err)
	}

	// locate the users table
	_, err = table.LocateUserTable(client)
	if err != nil {
		log.Panicf("failed to locate user table: %s", err)
	}

	// locate the api key table
	_, err = table.LocateApiKeyTable(client)
	if err != nil {
		log.Panicf("failed to locate API Key table: %s", err)
	}

	// locate the service routes table
	_, err = route.LocateRouteTable(client)
	if err != nil {
		log.Panicf("failed to locate service route table: %s", err)
	}

	// locate email verification table
	_, err = table.LocateEmailVerificationTable(client)
	if err != nil {
		log.Panicf("failed to locate email verification table: %s", err)
	}

	// locate Org Unit table
	_, err = table.LocateOrgUnitTable(client)
	if err != nil {
		log.Panicf("failed to locate Org Unit table: %s", err)
	}

	// ensure that the root tenant exists to work with as the default
	// tenancy
	locateRootTenant()

	// create a new keycloak client
	client, err := keycloak.New(conf.GetKeycloakEndpoint())
	if err != nil {
		// failed to create keycloak client, nothing more can be done
		log.Panicf("failed to create keycloak client: %s", err)
	}
	defer func() {
		_ = client.Logout(context.Background())
	}()

	// Initialize auth package, needs to be done before starting the
	// gateway service which in turn will be using auth package
	err = auth.Initialize(conf.GetKeycloakEndpoint(), "account")
	if err != nil {
		log.Panicf("failed to initialize auth package: %s", err)
	}

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

	// create user controller
	_, err = user.NewUserController(client)
	if err != nil {
		log.Panicf("failed to create user controller: %s", err)
	}

	// start email verification cleanup controller
	_, err = request.NewEmailVerificationCleanupController()
	if err != nil {
		log.Panicf("failed to create email verification cleanup controller: %s", err)
	}

	// role definition manager
	resourceMgr := roledef.NewResourceManager()

	// create GRPC Server context
	serverCtx := createGRPCServerContext()

	// setup resource definition server
	_ = server.NewResourceDefinitionServer(serverCtx, resourceMgr, APIEndpoint)

	// setup customer management server
	_ = server.NewCustomerServer(serverCtx, APIEndpoint)

	// Setup tenant management server
	_ = server.NewTenantServer(serverCtx, APIEndpoint)

	// Setup as new user server
	_ = server.NewUserServer(serverCtx, client, APIEndpoint)

	// Setup new tenant user server
	_ = server.NewTenantUserServer(serverCtx, client, APIEndpoint)

	// setup myaccount server
	_ = server.NewMyAccountServer(serverCtx, client, APIEndpoint)

	// setup registeration server
	_ = server.NewRegistrationServer(serverCtx, APIEndpoint)

	// setup Org Unit server
	_ = server.NewOrgUnitServer(serverCtx, APIEndpoint)

	// once all the servers are added to the list
	// start server
	startServerContext(serverCtx)
	log.Println("Initialization of Auth Gateway completed")

	sigc := make(chan os.Signal, 1)
	signal.Notify(sigc,
		syscall.SIGINT,
		syscall.SIGTERM,
		syscall.SIGQUIT)
	s := <-sigc
	log.Printf("Terminating Process got signal: %s", s)
}
