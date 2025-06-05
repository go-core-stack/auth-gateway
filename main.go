// Copyright © 2025 Prabhjot Singh Sethi, All Rights reserved
// Author: Prabhjot Singh Sethi <prabhjot.sethi@gmail.com>

package main

import (
	"context"
	"flag"
	"io/fs"
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

	"github.com/Prabhjot-Sethi/auth-gateway/api"
	"github.com/Prabhjot-Sethi/auth-gateway/pkg/auth"
	"github.com/Prabhjot-Sethi/auth-gateway/pkg/config"
	"github.com/Prabhjot-Sethi/auth-gateway/pkg/controller/tenant"
	"github.com/Prabhjot-Sethi/auth-gateway/pkg/controller/user"
	"github.com/Prabhjot-Sethi/auth-gateway/pkg/gateway"
	"github.com/Prabhjot-Sethi/auth-gateway/pkg/keycloak"
	"github.com/Prabhjot-Sethi/auth-gateway/pkg/model"
	"github.com/Prabhjot-Sethi/auth-gateway/pkg/server"
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

	// Port serving Auth Gateway
	GatewayPort = ":8090"

	// API Port for the server
	APIPort = ":8095"

	APIEndpoint = "http://localhost" + APIPort

	// GRPC Port for the server
	GrpcPort = ":8091"
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

func getSwaggerHandler() http.Handler {
	//mime.AddExtensionType(".svg", "image/svg+xml")
	// Use subdirectory in embedded files
	subFS, err := fs.Sub(api.Swagger, "swagger")
	if err != nil {
		panic("couldn't create sub filesystem: " + err.Error())
	}
	return http.FileServer(http.FS(subFS))
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

func startServerContext(serverCtx *model.GrpcServerContext, gwSwagger string) {
	go func() {
		lis, err := net.Listen("tcp", GrpcPort)
		if err != nil {
			log.Panicf("failed to start GRPC Server")
		}
		log.Panic(serverCtx.Server.Serve(lis))
	}()

	go func() {
		oa := getSwaggerHandler()
		gwHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.HasPrefix(r.URL.Path, "/api/") {
				// all APIs are handled via GRPC gateway
				serverCtx.Mux.ServeHTTP(w, r)
			} else {
				oa.ServeHTTP(w, r)
			}
		})
		lis, err := net.Listen("tcp", APIPort)
		if err != nil {
			log.Panicf("failed to start GRPC Gateway Server: %s", err)
		}
		log.Panic(http.Serve(lis, gwHandler))
	}()

	go func() {
		gw := gateway.New()
		oa := http.FileServer(http.Dir(gwSwagger))
		gwHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.HasPrefix(r.URL.Path, "/apidocs/") {
				oa.ServeHTTP(w, r)
			} else {
				// all APIs are handled via GRPC gateway
				gw.ServeHTTP(w, r)
			}
		})
		lis, err := net.Listen("tcp", GatewayPort)
		if err != nil {
			log.Panicf("failed to start Auth Gateway Server: %s", err)
		}
		log.Panic(http.Serve(lis, gwHandler))
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

	// Initialize auth package, needs to be done before starting the
	// gateway service which in turn will be using auth package
	err = auth.Initialize("http://localhost:8080", "account")
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

	// create GRPC Server context
	serverCtx := createGRPCServerContext()

	// Setup as new user server
	_ = server.NewUserServer(serverCtx, client, APIEndpoint)

	// setup myaccount server
	_ = server.NewMyAccountServer(serverCtx, client, APIEndpoint)

	// once all the servers are added to the list
	// start server
	startServerContext(serverCtx, conf.GetSwaggerDir())
	log.Println("Initialization of Auth Gateway completed")

	sigc := make(chan os.Signal, 1)
	signal.Notify(sigc,
		syscall.SIGINT,
		syscall.SIGTERM,
		syscall.SIGQUIT)
	s := <-sigc
	log.Printf("Terminating Process got signal: %s", s)
}
