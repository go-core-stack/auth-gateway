// Copyright © 2025 Prabhjot Singh Sethi, All Rights reserved
// Author: Prabhjot Singh Sethi <prabhjot.sethi@gmail.com>

package server

import (
	"context"
	"fmt"
	"log"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/Nerzal/gocloak/v13"
	"github.com/go-core-stack/auth-gateway/api"
	"github.com/go-core-stack/auth-gateway/pkg/keycloak"
	"github.com/go-core-stack/auth-gateway/pkg/model"
	auth "github.com/go-core-stack/auth/context"
	"github.com/go-core-stack/auth/route"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type MyTenantServer struct {
	api.UnimplementedMyTenantServer
	client *keycloak.Client
	// idpTable *table.IdentityProviderTable // REMOVED - using stubs instead
}

func (s *MyTenantServer) GetMyPasswordPolicy(ctx context.Context, req *api.MyPasswordPolicyGetReq) (*api.MyPasswordPolicyGetResp, error) {
	authInfo, _ := auth.GetAuthInfoFromContext(ctx)
	if authInfo == nil {
		return nil, status.Errorf(codes.Unauthenticated, "User not authenticated")
	}

	token, _ := s.client.GetAccessToken()
	realm, err := s.client.GetRealm(ctx, token, authInfo.Realm)
	if err != nil {
		// sanity check
		log.Printf("failed to get realm %s: %s", authInfo.Realm, err)
		return nil, status.Errorf(codes.Internal, "Something went wrong, please try again later")
	}
	resp := &api.MyPasswordPolicyGetResp{}
	tokens := strings.Split(gocloak.PString(realm.PasswordPolicy), " and ")
	for _, t := range tokens {
		var value int32
		re := regexp.MustCompile(`^([a-zA-Z_]\w*)\(([^)]+)\)$`)
		matches := re.FindStringSubmatch(t)
		if len(matches) != 3 {
			continue
		}

		key := matches[1]
		val, _ := strconv.Atoi(matches[2])
		value = int32(val)

		switch key {
		case "length":
			resp.MinLength = value
		case "maxLength":
			resp.MaxLength = value
		case "digits":
			resp.MinDigits = value
		case "lowerCase":
			resp.MinLower = value
		case "upperCase":
			resp.MinUpper = value
		case "specialChars":
			resp.MinSpecial = value
		case "passwordHistory":
			resp.RecentlyUsed = value
		case "passwordAge":
			resp.PasswordAge = value
		case "forceExpiredPasswordChange":
			resp.ForceExpirePasswordChange = value
		default:
			// ignore unknown keys
		}
	}
	return resp, nil
}

func (s *MyTenantServer) UpdateMyPasswordPolicy(ctx context.Context, req *api.MyPasswordPolicyUpdateReq) (*api.MyPasswordPolicyUpdateResp, error) {
	authInfo, _ := auth.GetAuthInfoFromContext(ctx)
	if authInfo == nil {
		return nil, status.Errorf(codes.Unauthenticated, "User not authenticated")
	}

	if req.MinLength < 4 {
		return nil, status.Errorf(codes.InvalidArgument, "minimum length should be at least 4")
	}

	if req.MaxLength > 40 {
		return nil, status.Errorf(codes.InvalidArgument, "maximum password length can not be more than 40")
	}

	if (req.MaxLength < req.MinLength) || (req.MinDigits+req.MinLower+req.MinSpecial+req.MinUpper > req.MaxLength) {
		return nil, status.Errorf(codes.InvalidArgument, "maximum length can not be less than minimum length")
	}

	// policy string would look like
	// forceExpiredPasswordChange(365) and passwordHistory(3) and length(8) and notUsername(undefined) and notEmail(undefined) and passwordAge(30) and notContainsUsername(undefined) and specialChars(1) and upperCase(1) and lowerCase(1) and digits(1) and maxLength(64)
	// by default always ensure notUsername, notEmail and notContainsUsername is present
	policy := fmt.Sprintf("length(%d) and maxLength(%d) and notUsername(undefined) and notEmail(undefined) and notContainsUsername(undefined)", req.MinLength, req.MaxLength)

	if req.MinDigits > 0 {
		policy += fmt.Sprintf(" and digits(%d)", req.MinDigits)
	}

	if req.MinLower > 0 {
		policy += fmt.Sprintf(" and lowerCase(%d)", req.MinLower)
	}

	if req.MinUpper > 0 {
		policy += fmt.Sprintf(" and upperCase(%d)", req.MinUpper)
	}

	if req.MinSpecial > 0 {
		policy += fmt.Sprintf(" and specialChars(%d)", req.MinSpecial)
	}

	if req.RecentlyUsed > 0 {
		policy += fmt.Sprintf(" and passwordHistory(%d)", req.RecentlyUsed)
	}

	if req.PasswordAge > 0 {
		policy += fmt.Sprintf(" and passwordAge(%d)", req.PasswordAge)
	}

	if req.ForceExpirePasswordChange > 0 {
		policy += fmt.Sprintf(" and forceExpiredPasswordChange(%d)", req.ForceExpirePasswordChange)
	}

	token, _ := s.client.GetAccessToken()
	_, err := s.client.GetRealm(ctx, token, authInfo.Realm)
	if err != nil {
		// sanity check
		log.Printf("failed to get realm %s: %s", authInfo.Realm, err)
		return nil, status.Errorf(codes.Internal, "Something went wrong, please try again later")
	}
	update := gocloak.RealmRepresentation{
		Realm:          gocloak.StringP(authInfo.Realm),
		PasswordPolicy: gocloak.StringP(policy),
	}

	err = s.client.UpdateRealm(ctx, token, update)
	if err != nil {
		log.Printf("failed to update password policy for realm %s: %s", authInfo.Realm, err)
		return nil, status.Errorf(codes.Internal, "Something went wrong, please try again later")
	}

	return &api.MyPasswordPolicyUpdateResp{}, nil
}

// Identity Provider Management Methods - STUB IMPLEMENTATIONS

func (s *MyTenantServer) GetMyIdentityProviderTypes(ctx context.Context, req *api.IdentityProviderTypesGetReq) (*api.IdentityProviderTypesGetResp, error) {
	// Return available provider types metadata
	allProviders := []*api.IdentityProviderTypesListEntry{
		{
			Type: "google",
		},
		{
			Type: "microsoft",
		},
	}

	return &api.IdentityProviderTypesGetResp{
		Providers: allProviders,
	}, nil
}

func (s *MyTenantServer) CreateMyIdentityProvider(ctx context.Context, req *api.MyIdentityProviderCreateReq) (*api.MyIdentityProviderCreateResp, error) {
	authInfo, _ := auth.GetAuthInfoFromContext(ctx)
	if authInfo == nil {
		return nil, status.Error(codes.Unauthenticated, "authentication required")
	}

	// Basic validation
	if strings.TrimSpace(req.Key) == "" {
		return nil, status.Error(codes.InvalidArgument, "identity provider key is required")
	}

	if req.Type == api.IdentityProviderDefs_IdentityProviderUnspecified {
		return nil, status.Error(codes.InvalidArgument, "provider type is required")
	}

	// STUB: Just return success without actual creation
	return &api.MyIdentityProviderCreateResp{}, nil
}

func (s *MyTenantServer) ListMyIdentityProviders(ctx context.Context, req *api.MyIdentityProvidersListReq) (*api.MyIdentityProvidersListResp, error) {
	authInfo, _ := auth.GetAuthInfoFromContext(ctx)
	if authInfo == nil {
		return nil, status.Error(codes.Unauthenticated, "authentication required")
	}

	// STUB: Return mock data
	mockInstances := []*api.MyIdentityProvidersListEntry{
		{
			Key:      "google-sso",
			DispName: "Google SSO",
			Type:     api.IdentityProviderDefs_Google,
			Enabled:  true,
			Created:  time.Now().Unix() - 86400, // 1 day ago
		},
		{
			Key:      "microsoft-sso",
			DispName: "Microsoft SSO",
			Type:     api.IdentityProviderDefs_Microsoft,
			Enabled:  false,
			Created:  time.Now().Unix() - 7200, // 2 hours ago
		},
	}

	// Apply filters if provided
	var filteredInstances []*api.MyIdentityProvidersListEntry
	for _, instance := range mockInstances {
		// Filter by provider type
		if req.Type != nil {
			if instance.Type != *req.Type {
				continue
			}
		}

		// Filter by enabled status
		if req.Enabled != nil {
			if instance.Enabled != *req.Enabled {
				continue
			}
		}

		filteredInstances = append(filteredInstances, instance)
	}

	// Apply pagination
	totalCount := len(filteredInstances)
	offset := int(req.GetOffset())
	limit := int(req.GetLimit())

	if limit <= 0 {
		limit = 10 // Default limit
	}

	start := offset
	if start > totalCount {
		start = totalCount
	}

	end := start + limit
	if end > totalCount {
		end = totalCount
	}

	pagedInstances := filteredInstances[start:end]

	return &api.MyIdentityProvidersListResp{
		Items: pagedInstances,
		Count: int32(totalCount),
	}, nil
}

func (s *MyTenantServer) GetMyIdentityProvider(ctx context.Context, req *api.MyIdentityProviderGetReq) (*api.MyIdentityProviderGetResp, error) {
	authInfo, _ := auth.GetAuthInfoFromContext(ctx)
	if authInfo == nil {
		return nil, status.Error(codes.Unauthenticated, "authentication required")
	}

	if strings.TrimSpace(req.Key) == "" {
		return nil, status.Error(codes.InvalidArgument, "identity provider key is required")
	}

	// STUB: Return mock data based on key
	switch req.Key {
	case "google-sso":
		return &api.MyIdentityProviderGetResp{
			Key:       "google-sso",
			DispName:  "Google SSO",
			Type:      api.IdentityProviderDefs_Google,
			Enabled:   true,
			Created:   time.Now().Unix() - 86400,
			CreatedBy: "admin",
			Google: &api.GoogleIDPConfig{
				ClientId:     "stub-google-client-id",
				ClientSecret: "stub-google-client-secret",
				HostedDomain: "example.com",
			},
		}, nil
	case "microsoft-sso":
		return &api.MyIdentityProviderGetResp{
			Key:       "microsoft-sso",
			DispName:  "Microsoft SSO",
			Type:      api.IdentityProviderDefs_Microsoft,
			Enabled:   false,
			Created:   time.Now().Unix() - 7200,
			CreatedBy: "admin",
			Microsoft: &api.MicrosoftIDPConfig{
				ClientId:     "stub-microsoft-client-id",
				ClientSecret: "stub-microsoft-client-secret",
				TenantId:     "common",
			},
		}, nil
	default:
		return nil, status.Errorf(codes.NotFound, "identity provider '%s' not found (STUB)", req.Key)
	}
}

func (s *MyTenantServer) UpdateMyIdentityProvider(ctx context.Context, req *api.MyIdentityProviderUpdateReq) (*api.MyIdentityProviderUpdateResp, error) {
	authInfo, _ := auth.GetAuthInfoFromContext(ctx)
	if authInfo == nil {
		return nil, status.Error(codes.Unauthenticated, "authentication required")
	}

	if strings.TrimSpace(req.Key) == "" {
		return nil, status.Error(codes.InvalidArgument, "identity provider key is required")
	}

	// STUB: Simulate checking if provider exists
	validKeys := []string{"google-sso", "microsoft-sso"}
	found := false
	for _, validKey := range validKeys {
		if req.Key == validKey {
			found = true
			break
		}
	}

	if !found {
		return nil, status.Errorf(codes.NotFound, "identity provider '%s' not found (STUB)", req.Key)
	}

	// STUB: Just return success without actual update
	return &api.MyIdentityProviderUpdateResp{}, nil
}

func (s *MyTenantServer) DeleteMyIdentityProvider(ctx context.Context, req *api.MyIdentityProviderDeleteReq) (*api.MyIdentityProviderDeleteResp, error) {
	authInfo, _ := auth.GetAuthInfoFromContext(ctx)
	if authInfo == nil {
		return nil, status.Error(codes.Unauthenticated, "authentication required")
	}

	if strings.TrimSpace(req.Key) == "" {
		return nil, status.Error(codes.InvalidArgument, "identity provider key is required")
	}

	// STUB: Simulate checking if provider exists
	validKeys := []string{"google-sso", "microsoft-sso"}
	found := false
	for _, validKey := range validKeys {
		if req.Key == validKey {
			found = true
			break
		}
	}

	if !found {
		return nil, status.Errorf(codes.NotFound, "identity provider '%s' not found (STUB)", req.Key)
	}

	// STUB: Just return success without actual deletion
	return &api.MyIdentityProviderDeleteResp{}, nil
}

// Helper methods for Identity Provider Management - REMOVED (STUBS DON'T NEED THESE)

func NewMyTenantServer(ctx *model.GrpcServerContext, client *keycloak.Client, ep string) *MyTenantServer {
	// REMOVED: Database dependency - using stubs instead
	// idpTbl, err := table.GetIdentityProviderTable()
	// if err != nil {
	//	log.Panicf("failed to get identity provider table: %s", err)
	// }

	srv := &MyTenantServer{
		client: client,
		// idpTable: idpTbl, // REMOVED - using stubs instead
	}
	api.RegisterMyTenantServer(ctx.Server, srv)
	err := api.RegisterMyTenantHandler(context.Background(), ctx.Mux, ctx.Conn)
	if err != nil {
		log.Panicf("failed to register handler: %s", err)
	}
	tbl, err := route.GetRouteTable()
	if err != nil {
		log.Panicf("failed to get route table: %s", err)
	}
	for _, r := range api.RoutesMyTenant {
		key := &route.Key{
			Url:    r.Url,
			Method: r.Method,
		}
		entry := &route.Route{
			Key:      key,
			Endpoint: ep,
			Resource: r.Resource,
			Verb:     r.Verb,
		}
		if err := tbl.Locate(context.Background(), key, entry); err != nil {
			log.Panicf("failed to register route %d %s: %s", r.Method, r.Url, err)
		}
	}
	return srv
}
