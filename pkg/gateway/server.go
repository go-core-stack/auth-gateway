// Copyright © 2025 Prabhjot Singh Sethi, All Rights reserved
// Author: Prabhjot Singh Sethi <prabhjot.sethi@gmail.com>

package gateway

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"os"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"golang.org/x/net/http2"
	"gopkg.in/natefinch/lumberjack.v2"

	"github.com/Nerzal/gocloak/v13"
	common "github.com/go-core-stack/auth/context"
	"github.com/go-core-stack/auth/hash"
	"github.com/go-core-stack/auth/route"
	"github.com/go-core-stack/core/errors"
	"github.com/go-core-stack/core/reconciler"
	"github.com/go-core-stack/core/utils"

	"github.com/go-core-stack/auth-gateway/pkg/auth"
	"github.com/go-core-stack/auth-gateway/pkg/keycloak"
	"github.com/go-core-stack/auth-gateway/pkg/table"
)

type gwContextKey string

const (
	authKey gwContextKey = "auth"
	ouKey   gwContextKey = "ou"

	// sessionCheckCacheDuration defines how long to cache session checks (30 seconds)
	sessionCheckCacheDuration = 30 * time.Second
)

// sessionCheckCache represents cached session check result
type sessionCheckCache struct {
	lastCheck time.Time
	mu        sync.RWMutex
}

// sessionCheckMap is a thread-safe map for caching session checks per user
type sessionCheckMap struct {
	cache map[string]*sessionCheckCache
	mu    sync.RWMutex
}

// newSessionCheckMap creates a new session check cache map
func newSessionCheckMap() *sessionCheckMap {
	return &sessionCheckMap{
		cache: make(map[string]*sessionCheckCache),
	}
}

// shouldCheckSessions determines if we should check sessions for a user
func (scm *sessionCheckMap) shouldCheckSessions(tenant, username string) bool {
	key := fmt.Sprintf("%s:%s", tenant, username)

	scm.mu.RLock()
	entry, exists := scm.cache[key]
	scm.mu.RUnlock()

	if !exists {
		return true
	}

	entry.mu.RLock()
	defer entry.mu.RUnlock()
	return time.Since(entry.lastCheck) > sessionCheckCacheDuration
}

// updateLastCheck updates the last check time for a user
func (scm *sessionCheckMap) updateLastCheck(tenant, username string) {
	key := fmt.Sprintf("%s:%s", tenant, username)

	scm.mu.Lock()
	if entry, exists := scm.cache[key]; exists {
		scm.mu.Unlock()
		entry.mu.Lock()
		entry.lastCheck = time.Now()
		entry.mu.Unlock()
	} else {
		scm.cache[key] = &sessionCheckCache{
			lastCheck: time.Now(),
		}
		scm.mu.Unlock()
	}
}

var logger *zap.Logger

type gateway struct {
	http.Handler
	validator       hash.Validator
	apiKeys         *table.ApiKeyTable
	userTbl         *table.UserTable
	routes          *route.RouteTable
	ouTbl           *table.OrgUnitTable
	ouUserTbl       *table.OrgUnitUserTable
	tenantTbl       *table.TenantTable
	keycloakClient  *keycloak.Client
	sessionCheckMap *sessionCheckMap
	proxyV1         *httputil.ReverseProxy
	proxyV2         *httputil.ReverseProxy
}

type gatewayReconciler struct {
	reconciler.Controller
	mu sync.Mutex
	gw *gateway
}

func (r *gatewayReconciler) Reconcile(k any) (*reconciler.Result, error) {
	ok := r.mu.TryLock()
	if !ok {
		return &reconciler.Result{}, nil
	}
	go func() {
		time.Sleep(10 * time.Second)
		r.mu.Unlock()
		populateRoutes(r.gw.routes)
	}()
	return &reconciler.Result{}, nil
}

func (s *gateway) AuthenticateRequest(r *http.Request) (*common.AuthInfo, error) {
	var authInfo *common.AuthInfo
	var user *table.UserEntry
	var err error
	now := time.Now().Unix()
	keyId := s.validator.GetKeyId(r)
	// check if an API key is used
	if keyId != "" {
		key := &table.ApiKeyId{
			Id: keyId,
		}
		entry, err := s.apiKeys.Find(r.Context(), key)
		if err != nil {
			if errors.IsNotFound(err) {
				return nil, errors.Wrapf(errors.Unauthorized, "Invalid Api Key")
			}
			return nil, errors.Wrapf(errors.Unauthorized, "Failed to perform auth at the moment")
		}
		if entry.UserInfo == nil {
			return nil, errors.Wrapf(errors.Unauthorized, "user not available")
		}
		if entry.Config.ExpireAt != 0 && entry.Config.ExpireAt < now {
			return nil, errors.Wrapf(errors.Unauthorized, "Api Key is %s expired", keyId)
		}
		_, err = s.validator.Validate(r, entry.Secret.Value)
		if err != nil {
			return nil, errors.Wrapf(errors.Unauthorized, "Invalid Signature")
		}

		uKey := &table.UserKey{
			Tenant:   entry.UserInfo.Tenant,
			Username: entry.UserInfo.Username,
		}
		user, err = s.userTbl.Find(r.Context(), uKey)
		if err != nil {
			if errors.IsNotFound(err) {
				return nil, errors.Wrapf(errors.Unauthorized, "User %s not found in tenant %s", entry.UserInfo.Username, entry.UserInfo.Tenant)
			}
			log.Printf("Failed to find user %s in tenant %s: %s", entry.UserInfo.Username, entry.UserInfo.Tenant, err)
			return nil, errors.Wrapf(errors.Unknown, "Something went wrong while processing request: %s", err)
		}

		authInfo = &common.AuthInfo{
			Realm:     user.Key.Tenant,
			UserName:  user.Key.Username,
			Email:     user.Info.Email,
			FirstName: user.Info.FirstName,
			LastName:  user.Info.LastName,
			FullName:  user.Info.FirstName + " " + user.Info.LastName,
		}

		// trigger an update to lastUsed timestamp for ApiKey
		if entry.LastUsed == 0 || (entry.LastUsed+60) <= now {
			update := &table.ApiKeyEntry{
				Key: table.ApiKeyId{
					Id: keyId,
				},
				LastUsed: now,
			}
			err = s.apiKeys.Update(r.Context(), &update.Key, update)
			if err != nil {
				log.Printf("Failed to update last access for user %s in tenant %s: %s", authInfo.UserName, authInfo.Realm, err)
			}
		}
	} else {
		var err error
		authInfo, err = auth.AuthenticateRequest(r, "")
		if err != nil {
			return nil, errors.Wrapf(errors.Unauthorized, "failed to authenticate incoming request: %s", err)
		}

		uKey := &table.UserKey{
			Tenant:   authInfo.Realm,
			Username: authInfo.UserName,
		}
		user, err = s.userTbl.Find(r.Context(), uKey)
		if err != nil {
			if !errors.IsNotFound(err) {
				log.Printf("Failed to find user %s in tenant %s: %s", authInfo.UserName, authInfo.Realm, err)
				return nil, errors.Wrapf(errors.Unknown, "Something went wrong while processing request: %s", err)
			}
			// locate a new user entry, to handle SSO created users
			update := &table.UserEntry{
				Key: &table.UserKey{
					Tenant:   authInfo.Realm,
					Username: authInfo.UserName,
				},
				Created: now,
				Updated: now,
				Info: &table.UserInfo{
					Email:     authInfo.Email,
					FirstName: authInfo.FirstName,
					LastName:  authInfo.LastName,
				},
			}
			err := s.userTbl.Locate(r.Context(), update.Key, update)
			if err != nil {
				log.Printf("Failed to locate user %s in tenant %s: %s", authInfo.UserName, authInfo.Realm, err)
				return nil, errors.Wrapf(errors.Unknown, "Something went wrong while processing request: %s", err)
			}
			user = update
		}

		// trigger an update to lastAccess timestamp
		if user.LastAccess == 0 || (user.LastAccess+60) <= now {
			update := &table.UserEntry{
				Key: &table.UserKey{
					Tenant:   authInfo.Realm,
					Username: authInfo.UserName,
				},
				LastAccess: now,
			}
			err = s.userTbl.Update(r.Context(), update.Key, update)
			if err != nil {
				log.Printf("Failed to update last access for user %s in tenant %s: %s", authInfo.UserName, authInfo.Realm, err)
			}
		}
	}

	if utils.PBool(user.Disabled) {
		return nil, errors.Wrapf(errors.Unauthorized, "User %s is disabled in tenant %s", authInfo.UserName, authInfo.Realm)
	}

	// Enforce session limits only for non-API key authentication
	if keyId == "" {
		err = s.enforceSessionLimits(r.Context(), authInfo)
		if err != nil {
			return nil, err
		}
	}

	// Add Auth info for the backend server
	err = common.SetAuthInfoHeader(r, authInfo)
	if err != nil {
		return nil, errors.Wrapf(errors.Unauthorized, "Failed to process auth information: %s", err)
	}
	return authInfo, nil
}

// enforceSessionLimits checks and enforces session limits for the authenticated user
func (s *gateway) enforceSessionLimits(ctx context.Context, authInfo *common.AuthInfo) error {
	// Skip if Keycloak client is not available
	if s.keycloakClient == nil {
		return nil
	}

	// Check if we should perform session limit check (use cache to avoid frequent checks)
	if !s.sessionCheckMap.shouldCheckSessions(authInfo.Realm, authInfo.UserName) {
		return nil
	}

	// Get tenant configuration
	tenantKey := &table.TenantKey{
		Name: authInfo.Realm,
	}

	tenant, err := s.tenantTbl.Find(ctx, tenantKey)
	if err != nil {
		log.Printf("failed to get tenant %s for session enforcement: %s", authInfo.Realm, err)
		// Don't fail the request due to tenant lookup error
		return nil
	}

	// Check if session limits are configured
	if tenant.SessionConfig == nil || tenant.SessionConfig.MaxConcurrentSessions <= 0 {
		return nil
	}

	// Get user's active sessions from Keycloak
	token, err := s.keycloakClient.GetAccessToken()
	if err != nil {
		log.Printf("failed to get Keycloak access token for session enforcement: %s", err)
		return nil
	}

	params := gocloak.GetUsersParams{
		Username: gocloak.StringP(authInfo.UserName),
	}
	users, err := s.keycloakClient.GetUsers(ctx, token, authInfo.Realm, params)
	if err != nil || len(users) == 0 {
		log.Printf("failed to get user %s from Keycloak for session enforcement: %s", authInfo.UserName, err)
		return nil
	}

	// Validate exact match for username
	if *users[0].Username != authInfo.UserName {
		log.Printf("username mismatch in Keycloak lookup for session enforcement")
		return nil
	}

	sessions, err := s.keycloakClient.GetUserSessions(ctx, token, authInfo.Realm, *users[0].ID)
	if err != nil {
		log.Printf("failed to get user sessions for %s: %s", authInfo.UserName, err)
		return nil
	}

	// Update cache to indicate we've checked recently
	s.sessionCheckMap.updateLastCheck(authInfo.Realm, authInfo.UserName)

	// Check if session limit is exceeded
	if int32(len(sessions)) > tenant.SessionConfig.MaxConcurrentSessions {
		switch tenant.SessionConfig.OnMaxSessionsExceeded {
		case table.TerminateOldest:
			// Sort sessions by start time and terminate the oldest
			sort.Slice(sessions, func(i, j int) bool {
				iStart := int64(0)
				jStart := int64(0)
				if sessions[i].Start != nil {
					iStart = *sessions[i].Start
				}
				if sessions[j].Start != nil {
					jStart = *sessions[j].Start
				}
				return iStart < jStart
			})

			// Terminate the oldest session
			if len(sessions) > 0 && sessions[0].ID != nil {
				err = s.keycloakClient.LogoutUserSession(ctx, token, authInfo.Realm, *sessions[0].ID)
				if err != nil {
					log.Printf("failed to terminate oldest session for user %s: %s", authInfo.UserName, err)
				} else {
					log.Printf("terminated oldest session for user %s due to session limit", authInfo.UserName)
				}
			}

		case table.DenyNew:
			// Find and terminate the newest session (which is likely the current one)
			sort.Slice(sessions, func(i, j int) bool {
				iStart := int64(0)
				jStart := int64(0)
				if sessions[i].Start != nil {
					iStart = *sessions[i].Start
				}
				if sessions[j].Start != nil {
					jStart = *sessions[j].Start
				}
				return iStart > jStart // Sort in descending order (newest first)
			})

			// Terminate the newest session
			if len(sessions) > 0 && sessions[0].ID != nil {
				err = s.keycloakClient.LogoutUserSession(ctx, token, authInfo.Realm, *sessions[0].ID)
				if err != nil {
					log.Printf("failed to terminate newest session for user %s: %s", authInfo.UserName, err)
				} else {
					log.Printf("terminated newest session for user %s due to session limit", authInfo.UserName)
				}
			}
			return errors.Wrapf(errors.Unauthorized, "Session limit exceeded. New session denied.")
		}
	}

	return nil
}

// performOrgUnitRoleCheck checks if the Org unit role associated with the user
// allows the requested access, returns true if the role allows access
func (s *gateway) performOrgUnitRoleCheck(authInfo *common.AuthInfo, ou string, r *http.Request) bool {
	ouUserKey := &table.OrgUnitUserKey{
		Tenant:    authInfo.Realm,
		Username:  authInfo.UserName,
		OrgUnitId: ou,
	}
	ouUser, err := s.ouUserTbl.Find(r.Context(), ouUserKey)
	if err != nil {
		if !errors.IsNotFound(err) {
			log.Printf("failed to find org unit user %v, got error: %s", ouUserKey, err)
		}
		return false
	}
	switch ouUser.Role {
	case "admin":
		// wildcard access to the org unit
		return true
	case "auditor":
		if r.Method == http.MethodGet || r.Method == http.MethodHead {
			// allow read-only access for auditor role
			return true
		}
		return false
	}
	return false
}

func (s *gateway) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var status int
	path := r.URL.RawPath
	if path == "" {
		// if the path does not contain such explicitly encoded
		// characters that would be lost during decoding,
		// RawPath will be an empty string
		path = r.URL.Path
	}
	match, orgUnit, err := matchRoute(r.Method, path)
	if err != nil {
		status = http.StatusNotFound
		http.Error(w, fmt.Sprintf("No route found for %s %s", r.Method, path), status)
		return
	}

	var authInfo *common.AuthInfo
	defer func() {
		if status != 0 {
			s.handleAccessLog(authInfo, orgUnit, r, status)
		}
	}()

	if match.isPublic {
		// even for public route ensure that we have auth info
		// set in the request header, so that backend server
		// can process the request correctly.
		// This is important for public routes that are used
		// ensuring uniform handling of gRPC gateway based
		// request processing, as it allows bypassing used gRPC
		// interceptors
		err = common.SetAuthInfoHeader(r, &common.AuthInfo{})
		if err != nil {
			status = http.StatusInternalServerError
			http.Error(w, fmt.Sprintf("Something went wrong: %s", err), status)
			return
		}
	} else {
		authInfo, err = s.AuthenticateRequest(r)
		if err != nil {
			status = http.StatusUnauthorized
			http.Error(w, fmt.Sprintf("Authentication failed: %s", err), status)
			return
		}
		newCtx := context.WithValue(r.Context(), authKey, *authInfo)
		newCtx = context.WithValue(newCtx, ouKey, orgUnit)
		r = r.WithContext(newCtx)
		if !match.isUserSpecific {
			if match.isRoot && !authInfo.IsRoot {
				// access to the route is meant to come only from root tenancy
				status = http.StatusForbidden
				http.Error(w, "Access Denied", status)
				return
			}
			// perform RBAC / PBAC and scope validations
			// TODO(prabhjot) currently only allow admin role
			isTenantAdmin := slices.Contains(authInfo.Roles, "admin")

			if !isTenantAdmin {
				allow := false
				if orgUnit != "" {
					// check if Org Unit Role associated with user, allows the
					// requested access
					allow = s.performOrgUnitRoleCheck(authInfo, orgUnit, r)
				}
				if !allow {
					status = http.StatusForbidden
					http.Error(w, "Access Denied", status)
					return
				}
			}
		}
		// validate Org unit scope irrespective if the match is
		// user specific or not
		if orgUnit != "" {
			//log.Printf("Checking access for org unit %s in tenant %s", orgUnit, authInfo.Realm)
			// check org unit is available and associated with tenant
			ouList, err := s.ouTbl.FindByTenant(r.Context(), authInfo.Realm, orgUnit)
			if err != nil {
				if errors.IsNotFound(err) {
					status = http.StatusNotFound
					http.Error(w, fmt.Sprintf("Org Unit %s not found", orgUnit), status)
					return
				}
				log.Printf("Failed to find org unit %s in tenant %s: %s", orgUnit, authInfo.Realm, err)
				status = http.StatusInternalServerError
				http.Error(w, "Something went wrong while processing request", status)
				return
			}
			if len(ouList) == 0 {
				status = http.StatusNotFound
				http.Error(w, fmt.Sprintf("Org Unit %s not found", orgUnit), status)
				return
			}
		}
	}

	r.URL.Scheme = match.scheme
	r.URL.Host = match.host
	// Set the Host header to match the URL host
	// This is important for the reverse proxy to work correctly
	// especially for HTTP/2 where the Host header is mandatory
	// and should match the authority of the request.
	// This is also important for HTTP/1.1 where the Host header
	// is used to determine the target host for the request.
	// This is required for the reverse proxy to work correctly
	// and to ensure that the backend server receives the correct
	// Host header.
	r.Host = r.URL.Host

	// support for HTTP/2 as well as HTTP/1.1
	if r.ProtoMajor == 2 {
		s.proxyV2.ServeHTTP(w, r)
	} else {
		s.proxyV1.ServeHTTP(w, r)
	}
}

// getClientIP currently assumes that the gateway is always behind a
// trusted proxy (nginx/UI pod) that sets X-Forwarded-For and X-Real-Ip
// headers if such headers are not present, it falls back to RemoteAddr
// which may not be reliable if the gateway is directly exposed to the
// internet.
// TODO(prabhjot) enhance this to support trusted proxy list
func getClientIP(r *http.Request) string {
	// Try X-Forwarded-For first
	xForwardedFor := r.Header.Get("X-Forwarded-For")
	if xForwardedFor != "" {
		// The header is a comma-separated list: client, proxy1, proxy2, ...
		ips := strings.Split(xForwardedFor, ",")
		return strings.TrimSpace(ips[0])
	}
	// Try X-Real-Ip if present
	if realIP := r.Header.Get("X-Real-Ip"); realIP != "" {
		return realIP
	}
	// Fallback to RemoteAddr
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil {
		return host
	}
	return r.RemoteAddr
}

// add ip address, user agent --
func (s *gateway) handleAccessLog(authInfo *common.AuthInfo, ou string, r *http.Request, status int) {
	path := r.URL.RawPath
	if path == "" {
		path = r.URL.Path
	}

	fields := []zap.Field{
		zap.String("method", r.Method),
		zap.Int("status", status),
	}

	if path != "" {
		fields = append(fields, zap.String("url", path))
	}
	if ou != "" {
		fields = append(fields, zap.String("ou", ou))
	}
	// add ip
	fields = append(fields, zap.String("ip", getClientIP(r)))

	// Add User-Agent
	if ua := r.UserAgent(); ua != "" {
		fields = append(fields, zap.String("user_agent", ua))
	}

	if authInfo != nil {
		if authInfo.UserName != "" {
			fields = append(fields, zap.String("username", authInfo.UserName))
		}
		if authInfo.Email != "" {
			fields = append(fields, zap.String("email", authInfo.Email))
		}
		if authInfo.Realm != "" {
			fields = append(fields, zap.String("tenant", authInfo.Realm))
		}
	}

	logger.Info("", fields...)
}

// currently this is only relevant for logging response
func (s *gateway) ModifyResponse(resp *http.Response) error {
	var authInfo *common.AuthInfo
	authInfoObj, ok := resp.Request.Context().Value(authKey).(common.AuthInfo)
	if ok {
		authInfo = &authInfoObj
	}
	ou, ok := resp.Request.Context().Value(ouKey).(string)
	if !ok {
		ou = ""
	}
	s.handleAccessLog(authInfo, ou, resp.Request, resp.StatusCode)
	return nil
}

func gatewayErrorHandler(w http.ResponseWriter, req *http.Request, err error) {
	log.Println("Auth gateway proxy received error", err)
	http.Error(w, "Service temporarily unavailable, please try after sometime", http.StatusServiceUnavailable)
}

// Create a new Auth Gateway server, wrapped around
// locally hosted insecure server
func New() http.Handler {
	apiKeys, err := table.GetApiKeyTable()
	if err != nil {
		log.Panicf("unable to get api keys table: %s", err)
	}

	userTbl, err := table.GetUserTable()
	if err != nil {
		log.Panicf("unable to get user table: %s", err)
	}

	routes, err := route.GetRouteTable()
	if err != nil {
		log.Panicf("unable to get route table: %s", err)
	}

	ouTbl, err := table.GetOrgUnitTable()
	if err != nil {
		log.Panicf("unable to get org unit table: %s", err)
	}

	ouUserTbl, err := table.GetOrgUnitUserTable()
	if err != nil {
		log.Panicf("unable to get org unit user table: %s", err)
	}

	tenantTbl, err := table.GetTenantTable()
	if err != nil {
		log.Panicf("unable to get tenant table: %s", err)
	}

	// For session enforcement, we need an admin Keycloak client
	// We'll use the same endpoint configuration as main.go
	keycloakBaseURL := os.Getenv("KEYCLOAK_BASE_URL")
	if keycloakBaseURL == "" {
		keycloakBaseURL = "http://localhost:8080" // fallback
	}

	keycloakClient, err := keycloak.New(keycloakBaseURL)
	if err != nil {
		log.Printf("failed to create Keycloak admin client for session enforcement: %s", err)
		keycloakClient = nil // Continue without session enforcement
	}

	director := func(req *http.Request) {
		// we don't use director we will handle request modification
		// of our own
	}

	// Transport for HTTP/1.1
	tr1 := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	// Transport for HTTP/2
	tr2 := &http2.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	gateway := &gateway{
		validator:       hash.NewValidator(300), // Allow an API request to be valid for 5 mins, to handle offer if any
		apiKeys:         apiKeys,
		userTbl:         userTbl,
		routes:          routes,
		ouTbl:           ouTbl,
		ouUserTbl:       ouUserTbl,
		tenantTbl:       tenantTbl,
		keycloakClient:  keycloakClient,
		sessionCheckMap: newSessionCheckMap(),
		proxyV1: &httputil.ReverseProxy{
			Director:     director,
			Transport:    tr1,
			ErrorHandler: gatewayErrorHandler,
		},
		proxyV2: &httputil.ReverseProxy{
			Director:     director,
			Transport:    tr2,
			ErrorHandler: gatewayErrorHandler,
		},
	}

	// set modify response handler for both v1 and v2 proxy
	gateway.proxyV1.ModifyResponse = gateway.ModifyResponse
	gateway.proxyV2.ModifyResponse = gateway.ModifyResponse

	r := &gatewayReconciler{
		gw: gateway,
	}

	err = routes.Register("GatewayController", r)
	if err != nil {
		log.Panicf("Failed to register GatewayController: %s", err)
	}
	return gateway
}

func init() {
	logDir := os.Getenv("LOGS_DIR")

	// ensure that a trailing slash is available
	if len(logDir) > 0 && logDir[len(logDir)-1] != '/' {
		logDir += "/"
	}

	encoderCfg := zap.NewProductionEncoderConfig() //we are using it for more customization
	//encoderCfg.TimeKey = "timestamp"
	//encoderCfg.MessageKey = "msg"
	//encoderCfg.EncodeTime = zapcore.ISO8601TimeEncoder
	encoderCfg.EncodeTime = zapcore.EpochTimeEncoder

	var core zapcore.Core

	if logDir == "" {
		// Log only to stdout
		core = zapcore.NewCore(
			zapcore.NewJSONEncoder(encoderCfg),
			zapcore.AddSync(os.Stdout),
			zapcore.InfoLevel,
		)
	} else {
		// Ensure log directory exists (optional)
		// _ = os.MkdirAll(filepath.Dir(logPath), 0777)

		lumberjackLogger := &lumberjack.Logger{
			Filename:   logDir + "access.log", // Log file path
			MaxSize:    10,                    // Max size in MB before rotation
			MaxBackups: 5,                     // Max number of old log files to keep
			MaxAge:     30,                    // Max age in days to keep a log file
			Compress:   true,                  // Compress old logs
		}

		core = zapcore.NewCore(
			zapcore.NewJSONEncoder(encoderCfg),
			zapcore.AddSync(lumberjackLogger),
			zapcore.InfoLevel,
		)
	}

	logger = zap.New(core).With(zap.String("_type", "AccessLog"))
}
