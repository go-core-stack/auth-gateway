// Copyright © 2025 Prabhjot Singh Sethi, All Rights reserved
// Author: Prabhjot Singh Sethi <prabhjot.sethi@gmail.com>

package gateway

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
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

// Pagination constants for buffering
const (
	MAX_LOOKAHEAD_PAGES  = 5
	MAX_ITEMS_TO_FETCH   = 200
	MIN_BUFFER_THRESHOLD = 0.5 // Fetch more if we have less than 50% of requested items
)

// filteringResponseWriter wraps http.ResponseWriter to intercept and filter responses
type filteringResponseWriter struct {
	http.ResponseWriter
	statusCode        int
	body              *bytes.Buffer
	shouldFilter      bool
	allowRules        []*table.ResourceMatch
	denyRules         []*table.ResourceMatch
	gateway           *gateway      // Reference to gateway for matchesResourceCriteria
	originalRequest   *http.Request // Original request for fetching additional pages
	requestedLimit    int           // User-requested limit for  buffering
	currentOffset     int           // Current offset for pagination
	totalItemsFetched int           // Total items fetched across all pages
}

func newFilteringResponseWriter(w http.ResponseWriter, shouldFilter bool, allowRules []*table.ResourceMatch, denyRules []*table.ResourceMatch, gw *gateway, r *http.Request) *filteringResponseWriter {
	return &filteringResponseWriter{
		ResponseWriter:    w,
		statusCode:        http.StatusOK,
		body:              &bytes.Buffer{},
		shouldFilter:      shouldFilter,
		allowRules:        allowRules,
		denyRules:         denyRules,
		gateway:           gw,
		originalRequest:   r,
		requestedLimit:    0, // Will be extracted from response
		currentOffset:     0,
		totalItemsFetched: 0,
	}
}

func (w *filteringResponseWriter) WriteHeader(statusCode int) {
	w.statusCode = statusCode
	// Don't write header yet ---> wait until we have filtered the body
}

func (w *filteringResponseWriter) Write(b []byte) (int, error) {
	if !w.shouldFilter || w.statusCode != http.StatusOK {
		// If we are not filtering or response is not OK then we can write directly
		if w.statusCode != http.StatusOK && w.body.Len() == 0 {
			w.ResponseWriter.WriteHeader(w.statusCode)
		}
		return w.ResponseWriter.Write(b)
	}
	// Buffer the response for filtering
	return w.body.Write(b)
}

func (w *filteringResponseWriter) finalize() {
	if !w.shouldFilter || w.statusCode != http.StatusOK || w.body.Len() == 0 {
		// If Nothing to filter
		if w.statusCode != http.StatusOK && w.body.Len() > 0 {
			w.ResponseWriter.WriteHeader(w.statusCode)
			if _, err := io.Copy(w.ResponseWriter, w.body); err != nil {
				log.Printf("failed to write response body: %v", err)
			}
		}
		return
	}

	// Try to parse and filter JSON response
	var data map[string]interface{}
	if err := json.Unmarshal(w.body.Bytes(), &data); err != nil {
		// If Not JSON or parse error ---> write original response
		w.ResponseWriter.WriteHeader(w.statusCode)
		if _, err := io.Copy(w.ResponseWriter, w.body); err != nil {
			log.Printf("failed to write response body: %v", err)
		}
		return
	}

	// Filter list if present
	filtered := w.filterList(data)

	// Write filtered response
	filteredBytes, err := json.Marshal(filtered)
	if err != nil {
		// Marshal error ---> write original response
		w.ResponseWriter.WriteHeader(w.statusCode)
		if _, err := io.Copy(w.ResponseWriter, w.body); err != nil {
			log.Printf("failed to write response body: %v", err)
		}
		return
	}

	// Update Content-Length header
	w.ResponseWriter.Header().Set("Content-Length", fmt.Sprintf("%d", len(filteredBytes)))
	w.ResponseWriter.WriteHeader(w.statusCode)
	if _, err := w.ResponseWriter.Write(filteredBytes); err != nil {
		log.Printf("failed to write filtered response: %v", err)
	}
}

func (w *filteringResponseWriter) filterList(data map[string]interface{}) map[string]interface{} {
	// Look for resource lists in various possible locations
	lists := []string{"items", "data", "results", "resources"}

	for _, key := range lists {
		if resources, ok := data[key]; ok {
			switch v := resources.(type) {
			case []interface{}:
				w.processResourceArray(data, key, v)
				return data

			case map[string]interface{}:
				if w.processNestedResources(data, key, v) {
					return data
				}
			}
		}
	}

	return data
}

// hasFilterRules checks if filtering is active
func (w *filteringResponseWriter) hasFilterRules() bool {
	return len(w.allowRules) > 0 || len(w.denyRules) > 0
}

// extractArray safely extracts an array from a map
func (w *filteringResponseWriter) extractArray(data map[string]interface{}, key string) ([]interface{}, bool) {
	if value, ok := data[key]; ok {
		if array, ok := value.([]interface{}); ok {
			return array, true
		}
	}
	return nil, false
}

// processResourceArray handles filtering for direct array case
func (w *filteringResponseWriter) processResourceArray(parent map[string]interface{}, key string, resources []interface{}) {
	w.extractPaginationParams(parent)
	w.totalItemsFetched = len(resources)

	filtered := w.filterResources(resources)

	//  buffering if filtering is active
	exhausted := !w.hasFilterRules() || w.requestedLimit == 0
	if !exhausted {
		filtered, exhausted = w.fetchUntilEnough(parent, filtered, key)
	}

	parent[key] = filtered
	w.updatePaginationMetadata(parent, exhausted, len(filtered))
}

// processNestedResources handles filtering for nested structure case
func (w *filteringResponseWriter) processNestedResources(parent map[string]interface{}, key string, dataMap map[string]interface{}) bool {
	nestedKeys := []string{"items", "data", "results", "resources"}
	for _, nestedKey := range nestedKeys {
		if resourceArray, ok := w.extractArray(dataMap, nestedKey); ok {
			w.extractPaginationParams(dataMap)
			w.totalItemsFetched = len(resourceArray)

			filtered := w.filterResources(resourceArray)

			exhausted := !w.hasFilterRules() || w.requestedLimit == 0
			if !exhausted {
				filtered, exhausted = w.fetchUntilEnough(dataMap, filtered, nestedKey)
			}

			dataMap[nestedKey] = filtered
			w.updatePaginationMetadata(dataMap, exhausted, len(filtered))
			return true
		}
	}
	return false
}

// extractPaginationParams extracts pagination parameters from the response
func (w *filteringResponseWriter) extractPaginationParams(data map[string]interface{}) {
	// Extract limit (requested page size)
	if limit, ok := data["limit"].(float64); ok {
		w.requestedLimit = int(limit)
	} else if limit, ok := data["pageSize"].(float64); ok {
		w.requestedLimit = int(limit)
	} else if limit, ok := data["per_page"].(float64); ok {
		w.requestedLimit = int(limit)
	}

	// Extract offset (current page offset)
	if offset, ok := data["offset"].(float64); ok {
		w.currentOffset = int(offset)
	} else if offset, ok := data["skip"].(float64); ok {
		w.currentOffset = int(offset)
	} else if page, ok := data["page"].(float64); ok {
		// Convert page number to offset: (page - 1) * limit
		if w.requestedLimit > 0 {
			w.currentOffset = (int(page) - 1) * w.requestedLimit
		}
	}
}

// fetchUntilEnough fetches additional pages until we have enough filtered results or hit limits
// Returns the aggregated filtered items and a boolean 'exhausted' which is true when backend pages are exhausted
func (w *filteringResponseWriter) fetchUntilEnough(originalData map[string]interface{}, currentFiltered []interface{}, resourceKey string) ([]interface{}, bool) {
	allFiltered := currentFiltered
	nextOffset := w.currentOffset + w.requestedLimit
	w.totalItemsFetched = w.requestedLimit

	for pagesFetched := 0; len(allFiltered) < w.requestedLimit &&
		pagesFetched < MAX_LOOKAHEAD_PAGES &&
		w.totalItemsFetched < MAX_ITEMS_TO_FETCH; pagesFetched++ {

		nextPageData, err := w.fetchNextPage(nextOffset, w.requestedLimit)
		if err != nil || nextPageData == nil {
			break
		}

		// Extract resources using helper function
		nextResources := w.extractResourcesFromResponse(nextPageData, resourceKey)
		if len(nextResources) == 0 {
			return allFiltered, true // Exhausted
		}

		// Filter and accumulate
		allFiltered = append(allFiltered, w.filterResources(nextResources)...)
		w.totalItemsFetched += len(nextResources)
		nextOffset += w.requestedLimit

		// Check if last page
		if len(nextResources) < w.requestedLimit {
			return allFiltered, true // Exhausted
		}
	}

	// Trim to requested limit if we fetched too many
	if len(allFiltered) > w.requestedLimit {
		allFiltered = allFiltered[:w.requestedLimit]
	}

	return allFiltered, false // Not exhausted
}

// extractResourcesFromResponse extracts resource array from response data
func (w *filteringResponseWriter) extractResourcesFromResponse(data map[string]interface{}, key string) []interface{} {
	value, ok := data[key]
	if !ok {
		return nil
	}

	// Direct array
	if array, ok := value.([]interface{}); ok {
		return array
	}

	// Nested structure
	if dataMap, ok := value.(map[string]interface{}); ok {
		nestedKeys := []string{"items", "data", "results", "resources"}
		for _, nestedKey := range nestedKeys {
			if array, ok := w.extractArray(dataMap, nestedKey); ok {
				return array
			}
		}
	}

	return nil
}

// fetchNextPage fetches the next page of results from the backend
func (w *filteringResponseWriter) fetchNextPage(offset, limit int) (map[string]interface{}, error) {
	// Clone the original request
	req := w.originalRequest.Clone(w.originalRequest.Context())

	// Update query parameters for the next page
	q := req.URL.Query()
	q.Set("offset", fmt.Sprintf("%d", offset))
	q.Set("limit", fmt.Sprintf("%d", limit))
	req.URL.RawQuery = q.Encode()

	// Create an HTTP client (reuse gateway's proxy settings)
	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // Match proxy config
		},
	}

	// Execute the request
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch next page: %w", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			log.Printf("failed to close response body: %v", err)
		}
	}()

	// Check status code
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("next page request failed with status: %d", resp.StatusCode)
	}

	// Parse JSON response
	var data map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return nil, fmt.Errorf("failed to decode next page response: %w", err)
	}

	return data, nil
}

// updatePaginationMetadata updates common pagination fields after filtering
// If exhausted==true, we've fetched all backend pages and can safely overwrite total counts
func (w *filteringResponseWriter) updatePaginationMetadata(data map[string]interface{}, exhausted bool, filteredCount int) {
	countFields := []string{"total", "totalCount", "count", "total_count", "totalItems", "total_items"}

	if exhausted {
		// Overwrite total fields when we've exhausted backend pages
		for _, field := range countFields {
			if _, ok := data[field]; ok {
				data[field] = float64(filteredCount)
			}
		}
	}

	// Always update returned count to match filtered results for this page
	if _, ok := data["returnedCount"]; ok {
		data["returnedCount"] = float64(filteredCount)
	}
	if _, ok := data["count"]; ok {
		data["count"] = float64(filteredCount)
	}

	// Note: We keep the original offset and limit as-is since those are user-requested values
}

func (w *filteringResponseWriter) filterResources(resources []interface{}) []interface{} {
	if !w.hasFilterRules() {
		return resources
	}

	filtered := make([]interface{}, 0, len(resources))
	for _, resource := range resources {
		resourceMap, ok := resource.(map[string]interface{})
		if !ok {
			filtered = append(filtered, resource)
			continue
		}

		resourceName := w.extractResourceName(resourceMap)
		if resourceName == "" {
			// Skip unnamed resources when filtering is active for security
			continue
		}

		if w.shouldShowResource(resourceName) {
			filtered = append(filtered, resource)
		}
	}

	return filtered
}

// extractResourceName extracts the resource identifier from a resource map
func (w *filteringResponseWriter) extractResourceName(resourceMap map[string]interface{}) string {
	// Priority order: name > id > key > generic identifiers
	nameFields := []string{"name", "Name", "id", "Id", "key", "Key", "resourceName", "identifier"}

	for _, field := range nameFields {
		if value, ok := resourceMap[field]; ok {
			if nameStr, ok := value.(string); ok && nameStr != "" {
				return nameStr
			}
		}
	}

	return ""
}

// shouldShowResource determines if a resource should be visible based on the filter rules
// Uses two-pass logic like permission validation: deny takes precedence, then check allows
func (w *filteringResponseWriter) shouldShowResource(resourceName string) bool {
	// First pass: Check deny rules - if any deny rule matches, hide the resource
	for _, rule := range w.denyRules {
		if w.gateway.matchesResourceCriteria(resourceName, rule) {
			return false // Deny takes precedence
		}
	}

	// Second pass: Check allow rules
	if len(w.allowRules) == 0 {
		// No allow rules means allow all (that aren't denied)
		return true
	}

	// Check if resource matches any allow rule
	for _, rule := range w.allowRules {
		if w.gateway.matchesResourceCriteria(resourceName, rule) {
			return true
		}
	}

	// No allow rule matched - hide the resource
	return false
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

	// Check if it's a custom role
	customRole, err := s.ouCustomRoleTbl.FindByNameAndOrgUnit(r.Context(), authInfo.Realm, ou, ouUser.Role)
	if err != nil {
		if !errors.IsNotFound(err) {
			log.Printf("failed to find custom role %s for org unit %s: %s", ouUser.Role, ou, err)
		}
		// If custom role not found, deny access
		return false
	}

	// Check if the custom role allows the requested action
	return s.checkCustomRolePermissions(customRole, r)
}

// getResourceFilterRules collects filtering rules for resources from the user's custom roles
// Returns separate lists of allow and deny rules for the specified resource type
func (s *gateway) getResourceFilterRules(authInfo *common.AuthInfo, ou string, resourceType string, r *http.Request) ([]*table.ResourceMatch, []*table.ResourceMatch) {
	// Validate inputs
	if authInfo == nil || ou == "" || resourceType == "" {
		return nil, nil
	}

	ouUserKey := &table.OrgUnitUserKey{
		Tenant:    authInfo.Realm,
		Username:  authInfo.UserName,
		OrgUnitId: ou,
	}

	ouUser, err := s.ouUserTbl.Find(r.Context(), ouUserKey)
	if err != nil {
		return nil, nil
	}

	// Only collect filter rules from custom roles
	if ouUser.Role == "admin" || ouUser.Role == "auditor" {
		return nil, nil
	}

	// Get the custom role
	customRole, err := s.ouCustomRoleTbl.FindByNameAndOrgUnit(r.Context(), authInfo.Realm, ou, ouUser.Role)
	if err != nil {
		return nil, nil
	}

	// Collect both Allow and Deny rules for the specified resource type
	var allowRules []*table.ResourceMatch
	var denyRules []*table.ResourceMatch

	for _, perm := range customRole.Permissions {
		// Skip non-matching resources early
		if perm.Resource != resourceType && perm.Resource != "*" {
			continue
		}

		// Skip permissions without match criteria
		if perm.Match == nil {
			continue
		}

		action := perm.Action
		if action == "" {
			action = "Allow"
		}

		switch action {
		case "Allow":
			allowRules = append(allowRules, perm.Match)
		case "Deny":
			denyRules = append(denyRules, perm.Match)
		}
	}

	return allowRules, denyRules
}

// matchesResourceCriteria checks if a resource name matches the given criteria
func (s *gateway) matchesResourceCriteria(resourceName string, match *table.ResourceMatch) bool {
	// Default to wildcard matching if no match criteria specified
	if match == nil {
		return true // Match all if no criteria specified
	}

	// Special case: empty resource name (list operations) always matches
	// This allows list operations to pass permission checks, while filtering
	// will be applied to the response to hide non-matching resources
	// NOTE: This should only apply to ALLOW rules. DENY rules should not match empty strings.
	if resourceName == "" {
		return true
	}

	key := match.Key
	criteria := match.Criteria

	// Default to wildcard if criteria is empty
	if criteria == "" {
		criteria = "wildcard"
	}

	var result bool
	switch criteria {
	case "exact":
		// Exact match
		result = resourceName == key

	case "prefix":
		// Resource name starts with the key
		result = strings.HasPrefix(resourceName, key)

	case "suffix":
		// Resource name ends with the key
		result = strings.HasSuffix(resourceName, key)

	case "regex":
		// Regex pattern matching
		matched, err := regexp.MatchString(key, resourceName)
		if err != nil {
			log.Printf("invalid regex pattern '%s': %s", key, err)
			return false
		}
		result = matched

	case "wildcard":
		// Wildcard matching with * support
		if key == "*" {
			return true // Match everything
		}

		// Convert wildcard pattern to regex
		// Escape special regex characters except *
		pattern := regexp.QuoteMeta(key)
		// Replace escaped \* with .*
		pattern = strings.ReplaceAll(pattern, "\\*", ".*")
		// Anchor the pattern
		pattern = "^" + pattern + "$"

		matched, err := regexp.MatchString(pattern, resourceName)
		if err != nil {
			log.Printf("error matching wildcard pattern '%s': %s", key, err)
			return false
		}
		result = matched

	default:
		// Unknown criteria, default to exact match
		log.Printf("unknown matching criteria '%s', defaulting to exact match", criteria)
		result = resourceName == key
	}

	return result
}

// checkCustomRolePermissions validates if a custom role permits the requested HTTP action
func (s *gateway) checkCustomRolePermissions(customRole *table.OrgUnitCustomRole, r *http.Request) bool {
	// Extract route info for permission checking
	routeInfo, err := s.extractRouteInfo(r)
	if err != nil {
		log.Printf("failed to extract route info for permission check: %s", err)
		return false // Deny access if we can't determine the resource
	}

	return s.validatePermissions(customRole, routeInfo)
}

// validatePermissions checks if the custom role allows access to the given resource/verb
// Supports multiple matching criteria (exact, prefix, suffix, regex, wildcard)
// Processes Allow/Deny actions with Deny taking precedence
func (s *gateway) validatePermissions(customRole *table.OrgUnitCustomRole, routeInfo *RouteInfo) bool {
	var hasAllowMatch bool

	// First pass: check for any Deny rules that match
	// Deny takes precedence, so we check all permissions for Deny first
	// NOTE: Skip Deny rules for list operations (empty ResourceName) ---> they only apply to individual resources
	if routeInfo.ResourceName != "" {
		for i, permission := range customRole.Permissions {
			// Check if resource type matches
			if permission.Resource != "*" && permission.Resource != routeInfo.Resource {
				continue
			}

			// Check if resource name matches using the matching criteria
			if permission.Match != nil {
				if !s.matchesResourceCriteria(routeInfo.ResourceName, permission.Match) {
					continue
				}
			}

			// Check if verb matches (exact match or wildcard)
			for _, allowedVerb := range permission.Verbs {
				verbMatches := allowedVerb == "*" || allowedVerb == routeInfo.Verb

				if verbMatches {
					// Check action type (default to "Allow" if not specified for backward compatibility)
					action := permission.Action
					if action == "" {
						action = "Allow"
					}

					if action == "Deny" {
						// Deny takes precedence - immediately reject access
						return false
					}
				}
			}
			_ = i // Suppress unused variable warning
		}
	}

	// Second pass: check for Allow rules that match
	for i, permission := range customRole.Permissions {
		// Check if resource type matches
		if permission.Resource != "*" && permission.Resource != routeInfo.Resource {
			continue
		}

		// Check if resource name matches using the matching criteria
		if permission.Match != nil {
			if !s.matchesResourceCriteria(routeInfo.ResourceName, permission.Match) {
				continue
			}
		}

		// Check if verb matches (exact match or wildcard)
		for _, allowedVerb := range permission.Verbs {
			verbMatches := allowedVerb == "*" || allowedVerb == routeInfo.Verb

			if verbMatches {
				// Check action type (default to "Allow" if not specified for backward compatibility)
				action := permission.Action
				if action == "" {
					action = "Allow"
				}

				if action == "Allow" {
					hasAllowMatch = true
					break
				}
			}
		}

		// If we found an Allow, no need to continue checking
		if hasAllowMatch {
			break
		}
		_ = i // Suppress unused variable warning
	}

	// Grant access only if there's an Allow match
	return hasAllowMatch
}

// RouteInfo holds information about the current request route
type RouteInfo struct {
	Resource     string // The resource type being accessed (e.g., "s3-bucket", "s3-object")
	ResourceName string // The specific resource name/identifier (e.g., "bucket-name", "object-key")
	Verb         string // The action being performed
}

// extractRouteInfo extracts resource and verb information from the current request
func (s *gateway) extractRouteInfo(r *http.Request) (*RouteInfo, error) {
	// Select the path to use, mirroring ServeHTTP's logic for encoded paths
	path := r.URL.RawPath
	if path == "" {
		// if the path does not contain such explicitly encoded
		// characters that would be lost during decoding,
		// RawPath will be an empty string
		path = r.URL.Path
	}

	// Use the existing matchRoute function for efficient route matching
	routeData, _, err := matchRoute(r.Method, path)
	if err != nil {
		return nil, err
	}

	// Extract resource name from URL path parameters
	// This will extract identifiers like bucket names, object keys, etc.
	resourceName := s.extractResourceName(path, routeData.resource)

	return &RouteInfo{
		Resource:     routeData.resource, // Resource type from route config
		ResourceName: resourceName,       // Specific resource identifier
		Verb:         routeData.verb,     // Verb from route config
	}, nil
}

// extractResourceName extracts the specific resource identifier from the URL path
// For example, from "/api/object-storage/v1/ou/xxx/bucket/my-bucket", it extracts "my-bucket"
func (s *gateway) extractResourceName(path string, resourceType string) string {
	// Split path into segments
	segments := strings.Split(strings.Trim(path, "/"), "/")

	// Look for common resource identifier patterns based on resource type
	switch resourceType {
	case "s3-bucket":
		// Extract bucket name: /api/object-storage/v1/ou/{ou}/bucket/{bucketName}
		for i, seg := range segments {
			if seg == "bucket" && i+1 < len(segments) {
				return segments[i+1]
			}
		}

	case "s3-object":
		// Extract object key: /api/object-storage/v1/ou/{ou}/bucket/{bucketName}/object/{objectKey}
		// or /api/object-storage/v1/ou/{ou}/bucket/{bucketName}/objects
		for i, seg := range segments {
			if seg == "object" && i+1 < len(segments) {
				return segments[i+1]
			}
			// For list operations, we might want to use bucket name
			if seg == "objects" && i > 0 && segments[i-2] == "bucket" {
				return segments[i-1] // Return bucket name for object list operations
			}
		}

	case "org-unit":
		// Extract org unit ID from path
		for i, seg := range segments {
			if seg == "ou" && i+1 < len(segments) {
				return segments[i+1]
			}
		}

	case "user":
		// Extract username from path
		for i, seg := range segments {
			if seg == "user" && i+1 < len(segments) {
				return segments[i+1]
			}
		}
	}

	// Default: return empty string if no specific resource identifier found
	return ""
}

func (s *gateway) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var status int
	var authInfo *common.AuthInfo
	var orgUnit string

	defer func() {
		if status != 0 {
			s.handleAccessLog(authInfo, orgUnit, r, status)
		}
	}()

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

	// Check if we need to filter the response based on resource matching rules
	var responseWriter = w
	if authInfo != nil && orgUnit != "" {
		// Extract route info to determine resource type
		routeInfo, err := s.extractRouteInfo(r)
		if err == nil && routeInfo.Verb == "list" {
			// Get filter rules for this resource type
			allowRules, denyRules := s.getResourceFilterRules(authInfo, orgUnit, routeInfo.Resource, r)
			if len(allowRules) > 0 || len(denyRules) > 0 {
				filteringWriter := newFilteringResponseWriter(w, true, allowRules, denyRules, s, r)
				responseWriter = filteringWriter
				// Ensure finalize is called after proxy completes
				defer filteringWriter.finalize()
			}
		}
	}

	// support for HTTP/2 as well as HTTP/1.1
	if r.ProtoMajor == 2 {
		s.proxyV2.ServeHTTP(responseWriter, r)
	} else {
		s.proxyV1.ServeHTTP(responseWriter, r)
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
