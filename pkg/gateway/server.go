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
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"golang.org/x/net/http2"
	"gopkg.in/natefinch/lumberjack.v2"

	common "github.com/go-core-stack/auth/context"
	"github.com/go-core-stack/auth/hash"
	"github.com/go-core-stack/auth/route"
	"github.com/go-core-stack/core/errors"
	"github.com/go-core-stack/core/reconciler"
	"github.com/go-core-stack/core/utils"

	"github.com/go-core-stack/auth-gateway/pkg/auth"
	"github.com/go-core-stack/auth-gateway/pkg/table"
)

type gwContextKey string

const (
	authKey gwContextKey = "auth"
	ouKey   gwContextKey = "ou"
)

var logger *zap.Logger

type gateway struct {
	http.Handler
	validator       hash.Validator
	apiKeys         *table.ApiKeyTable
	userTbl         *table.UserTable
	tenantTbl       *table.TenantTable
	routes          *route.RouteTable
	ouTbl           *table.OrgUnitTable
	ouUserTbl       *table.OrgUnitUserTable
	ouCustomRoleTbl *table.OrgUnitCustomRoleTable
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

		// Populate IsRoot and Roles from database (stored during bearer token auth)
		tenantKey := &table.TenantKey{
			Name: user.Key.Tenant,
		}
		tenant, err := s.tenantTbl.Find(r.Context(), tenantKey)
		if err != nil {
			if !errors.IsNotFound(err) {
				log.Printf("Failed to find tenant %s: %s", user.Key.Tenant, err)
			}
			authInfo.IsRoot = false
		} else if tenant.Config != nil {
			authInfo.IsRoot = tenant.Config.IsRoot
		}

		// Use roles stored in database from last bearer token login
		if user.RealmRoles != nil {
			authInfo.Roles = *user.RealmRoles
		} else {
			authInfo.Roles = []string{}
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

		// trigger an update to lastAccess timestamp and store roles
		if user.LastAccess == 0 || (user.LastAccess+60) <= now {
			update := &table.UserEntry{
				Key: &table.UserKey{
					Tenant:   authInfo.Realm,
					Username: authInfo.UserName,
				},
				LastAccess: now,
				RealmRoles: &authInfo.Roles, // Store roles from bearer token
			}
			err = s.userTbl.Update(r.Context(), update.Key, update)
			if err != nil {
				log.Printf("Failed to update last access for user %s in tenant %s: %s", authInfo.UserName, authInfo.Realm, err)
			}
		}
	}

	if utils.Dereference(user.Disabled) {
		return nil, errors.Wrapf(errors.Unauthorized, "User %s is disabled in tenant %s", authInfo.UserName, authInfo.Realm)
	}

	// Add Auth info for the backend server
	err = common.SetAuthInfoHeader(r, authInfo)
	if err != nil {
		return nil, errors.Wrapf(errors.Unauthorized, "Failed to process auth information: %s", err)
	}
	return authInfo, nil
}

// performOrgUnitRoleCheck checks if the Org unit role associated with the user
// allows the requested access, returns true if the role allows access
// For non-list operations, resourceInstance is the name/id of the specific resource being accessed
func (s *gateway) performOrgUnitRoleCheck(authInfo *common.AuthInfo, ou string, resource, verb, resourceInstance string, r *http.Request) bool {
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

	// Handle built-in roles
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

	// Check custom role permissions
	customRole, err := s.ouCustomRoleTbl.FindByNameAndOrgUnit(r.Context(), authInfo.Realm, ou, ouUser.Role)
	if err != nil {
		if !errors.IsNotFound(err) {
			log.Printf("failed to find custom role %s for org unit %s: %s", ouUser.Role, ou, err)
		}
		return false
	}

	// Evaluate permissions
	return s.evaluateCustomRolePermissions(customRole.Permissions, resource, verb, resourceInstance)
}

// evaluateCustomRolePermissions checks if the custom role's permissions allow the requested resource and verb
// For non-list operations, resourceInstance is checked against the permission's match criteria
func (s *gateway) evaluateCustomRolePermissions(permissions []*table.RolePermission, resource, verb, resourceInstance string) bool {
	var allowMatched bool
	var denyMatched bool

	for _, perm := range permissions {
		// Check if resource matches
		if !s.matchesResource(perm.Resource, perm.Match, resource) {
			continue
		}

		// Check if verb matches
		verbMatches := false
		for _, allowedVerb := range perm.Verbs {
			if allowedVerb == "*" || allowedVerb == verb {
				verbMatches = true
				break
			}
		}

		if !verbMatches {
			continue
		}

		// For non-list operations, check if the resource instance matches the criteria
		// List operations skip instance matching (show all, filter on individual access)
		if verb != "list" && resourceInstance != "" {
			if !s.matchesResourceInstance(resourceInstance, perm.Match) {
				continue
			}
		}

		// Apply action (Deny takes precedence)
		switch perm.Action {
		case table.RolePermissionActionDeny:
			denyMatched = true
		case table.RolePermissionActionAllow:
			allowMatched = true
		case table.RolePermissionActionLog:
			// Log action allows access but logs for audit
			allowMatched = true
		}
	}

	// Deny takes precedence over Allow
	if denyMatched {
		return false
	}

	return allowMatched
}

// matchesResource checks if a requested resource matches the permission's resource pattern
// This function performs resource type matching (e.g., "s3-object", "bucket")
func (s *gateway) matchesResource(permResource string, match *table.ResourceMatch, requestedResource string) bool {
	// Handle wildcard resource matching (e.g., "*" matches all resources)
	if permResource == "*" {
		return true
	}

	// Simple equality check - does the permission resource match the requested resource?
	return permResource == requestedResource
}

// matchesResourceInstance checks if a resource instance name matches the permission's match criteria
// Returns true if the instance matches the criteria, or if no criteria is specified
func (s *gateway) matchesResourceInstance(instanceName string, match *table.ResourceMatch) bool {
	// If no match criteria specified, allow all instances of this resource type
	if match == nil || match.Key == "" {
		return true
	}

	switch match.Criteria {
	case table.ResourceMatchCriteriaExact:
		return instanceName == match.Key

	case table.ResourceMatchCriteriaPrefix:
		return strings.HasPrefix(instanceName, match.Key)

	case table.ResourceMatchCriteriaSuffix:
		return strings.HasSuffix(instanceName, match.Key)

	case table.ResourceMatchCriteriaRegex:
		matched, err := regexp.MatchString(match.Key, instanceName)
		if err != nil {
			log.Printf("Invalid regex pattern %s: %s", match.Key, err)
			return false
		}
		return matched

	case table.ResourceMatchCriteriaAny, "*", "":
		// Default to Any/wildcard matching
		// Convert wildcard pattern to regex
		pattern := strings.ReplaceAll(match.Key, "*", ".*")
		pattern = "^" + pattern + "$"
		matched, err := regexp.MatchString(pattern, instanceName)
		if err != nil {
			log.Printf("Invalid wildcard pattern %s: %s", match.Key, err)
			return false
		}
		return matched

	default:
		log.Printf("Unknown match criteria: %s", match.Criteria)
		return false
	}
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
	match, orgUnit, keys, values, err := matchRoute(r.Method, path)
	if err != nil {
		status = http.StatusNotFound
		http.Error(w, fmt.Sprintf("No route found for %s %s", r.Method, path), status)
		return
	}

	// Extract resource instance name from URL path parameters
	// Common patterns: /bucket/{name}, /s3-object/{name}, /user/{username}
	resourceInstance := ""
	for i, k := range keys {
		// Look for common resource identifier keys
		if k == "name" || k == "id" || k == "username" || k == "bucket" || k == "object" {
			resourceInstance = values[i]
			break
		}
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
					allow = s.performOrgUnitRoleCheck(authInfo, orgUnit, match.resource, match.verb, resourceInstance, r)
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

	ouCustomRoleTbl, err := table.GetOrgUnitCustomRoleTable()
	if err != nil {
		log.Panicf("unable to get org unit custom role table: %s", err)
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
		tenantTbl:       tenantTbl,
		routes:          routes,
		ouTbl:           ouTbl,
		ouUserTbl:       ouUserTbl,
		ouCustomRoleTbl: ouCustomRoleTbl,
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
