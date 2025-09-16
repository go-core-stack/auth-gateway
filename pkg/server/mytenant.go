// Copyright © 2025 Prabhjot Singh Sethi, All Rights reserved
// Author: Prabhjot Singh Sethi <prabhjot.sethi@gmail.com>

package server

import (
	"context"
	"errors"
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

// Identity Provider Management Methods

func (s *MyTenantServer) GetMyIdentityProviderTypes(ctx context.Context, req *api.IdentityProviderTypesGetReq) (*api.IdentityProviderTypesGetResp, error) {
	resp := &api.IdentityProviderTypesGetResp{
		Providers: []*api.IdentityProviderTypesListEntry{},
	}
	for k, v := range api.IdentityProviderDefs_Type_name {
		if k == int32(api.IdentityProviderDefs_IdentityProviderUnspecified) {
			continue
		}
		resp.Providers = append(resp.Providers, &api.IdentityProviderTypesListEntry{Type: v})
	}
	// Return available provider types metadata

	return resp, nil
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

	// validate key format (only alphanumeric, hyphens, underscores)
	keyRegex := regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)
	if !keyRegex.MatchString(req.Key) {
		return nil, status.Error(codes.InvalidArgument, "identity provider key must contain only alphanumeric characters, hyphens, and underscores")
	}

	// key length limits
	if len(req.Key) < 2 || len(req.Key) > 50 {
		return nil, status.Error(codes.InvalidArgument, "identity provider key must be between 2 and 50 characters")
	}

	if req.Type == api.IdentityProviderDefs_IdentityProviderUnspecified {
		return nil, status.Error(codes.InvalidArgument, "provider type is required")
	}

	// Use Alias(Key) as display name if not provided
	displayName := strings.TrimSpace(req.DispName)
	if displayName == "" {
		displayName = req.Key
	}

	// display name length limit check
	if len(displayName) > 30 {
		return nil, status.Error(codes.InvalidArgument, "display name must not exceed 30 characters")
	}

	token, err := s.client.GetAccessToken()
	if err != nil {
		log.Printf("failed to get access token: %s", err)
		return nil, status.Error(codes.Internal, "authentication failed")
	}

	// Create identity provider based on type
	switch req.Type {
	case api.IdentityProviderDefs_Google:
		if req.Google == nil {
			return nil, status.Error(codes.InvalidArgument, "Google configuration is required")
		}
		if req.Google.ClientId == "" || req.Google.ClientSecret == "" {
			return nil, status.Error(codes.InvalidArgument, "Google client ID and secret are required")
		}

		// validate Google client ID format (should end with .googleusercontent.com)
		if !strings.HasSuffix(req.Google.ClientId, ".googleusercontent.com") {
			return nil, status.Error(codes.InvalidArgument, "Google client ID must end with .googleusercontent.com")
		}

		// Validate hosted domain format if provided
		if req.Google.HostedDomain != "" {
			domainRegex := regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9]*\.([a-zA-Z]{2,})+$`)
			if !domainRegex.MatchString(req.Google.HostedDomain) {
				return nil, status.Error(codes.InvalidArgument, "hosted domain must be a valid domain name")
			}
		}

		// Build Google IDP configuration
		idpConfig := map[string]string{
			"clientId":     req.Google.ClientId,
			"clientSecret": req.Google.ClientSecret,
			// Store creation metadata
			"createdAt": fmt.Sprintf("%d", time.Now().Unix()),
			"createdBy": authInfo.UserName,
		}

		if req.Google.HostedDomain != "" {
			idpConfig["hostedDomain"] = req.Google.HostedDomain
		}

		idpRep := gocloak.IdentityProviderRepresentation{
			Alias:       &req.Key,
			DisplayName: &displayName,
			ProviderID:  gocloak.StringP("google"),
			Enabled:     gocloak.BoolP(req.Enabled),
			Config:      &idpConfig,
		}

		_, err = s.client.CreateIdentityProvider(ctx, token, authInfo.Realm, idpRep)
		if err != nil {
			log.Printf("failed to create Google identity provider: %s", err)
			return nil, status.Error(codes.Internal, "failed to create identity provider")
		}

	case api.IdentityProviderDefs_Microsoft:
		if req.Microsoft == nil {
			return nil, status.Error(codes.InvalidArgument, "Microsoft configuration is required")
		}
		if req.Microsoft.ClientId == "" || req.Microsoft.ClientSecret == "" {
			return nil, status.Error(codes.InvalidArgument, "Microsoft client ID and secret are required")
		}

		// validate Microsoft client ID format (should be a GUID)
		guidRegex := regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
		if !guidRegex.MatchString(req.Microsoft.ClientId) {
			return nil, status.Error(codes.InvalidArgument, "Microsoft client ID must be a valid GUID format")
		}

		// Validate tenant ID format if provided
		if req.Microsoft.TenantId != "" {
			// Tenant ID can be a GUID, domain name, or special azure AD value.
			isSpecialValue := req.Microsoft.TenantId == "common" || req.Microsoft.TenantId == "organizations" || req.Microsoft.TenantId == "consumers"
			isGUID := guidRegex.MatchString(req.Microsoft.TenantId)

			if !isSpecialValue && !isGUID {
				// Check if it's a valid domain name
				domainRegex := regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9]*\.([a-zA-Z]{2,})+$`)
				if !domainRegex.MatchString(req.Microsoft.TenantId) {
					return nil, status.Error(codes.InvalidArgument, "Microsoft tenant ID must be a valid GUID, domain name, or one of: common, organizations, consumers")
				}
			}
		}

		// Build Microsoft IDP configuration
		idpConfig := map[string]string{
			"clientId":     req.Microsoft.ClientId,
			"clientSecret": req.Microsoft.ClientSecret,
			// Store creation metadata
			"createdAt": fmt.Sprintf("%d", time.Now().Unix()),
			"createdBy": authInfo.UserName,
		}

		if req.Microsoft.TenantId != "" {
			idpConfig["tenantId"] = req.Microsoft.TenantId
		}

		idpRep := gocloak.IdentityProviderRepresentation{
			Alias:       &req.Key,
			DisplayName: &displayName,
			ProviderID:  gocloak.StringP("microsoft"),
			Enabled:     gocloak.BoolP(req.Enabled),
			Config:      &idpConfig,
		}

		_, err = s.client.CreateIdentityProvider(ctx, token, authInfo.Realm, idpRep)
		if err != nil {
			log.Printf("failed to create Microsoft identity provider: %s", err)
			return nil, status.Error(codes.Internal, "failed to create identity provider")
		}

	default:
		return nil, status.Error(codes.InvalidArgument, "unsupported provider type")
	}

	return &api.MyIdentityProviderCreateResp{}, nil
}

func (s *MyTenantServer) ListMyIdentityProviders(ctx context.Context, req *api.MyIdentityProvidersListReq) (*api.MyIdentityProvidersListResp, error) {
	authInfo, _ := auth.GetAuthInfoFromContext(ctx)
	if authInfo == nil {
		return nil, status.Error(codes.Unauthenticated, "authentication required")
	}

	token, err := s.client.GetAccessToken()
	if err != nil {
		log.Printf("failed to get access token: %s", err)
		return nil, status.Error(codes.Internal, "authentication failed")
	}

	// Get identity providers from Keycloak
	idps, err := s.client.GetIdentityProviders(ctx, token, authInfo.Realm)
	if err != nil {
		var apiErr gocloak.APIError
		if errors.As(err, &apiErr) {
			switch apiErr.Code {
			case 401:
				return nil, status.Error(codes.Unauthenticated, "unauthorized")
			case 403:
				return nil, status.Error(codes.PermissionDenied, "permission denied")
			case 404:
				return nil, status.Error(codes.NotFound, "resource not found")
			default:
				// fallthrough
			}
		}
		log.Printf("failed to list identity providers: %s", err)
		return nil, status.Error(codes.Internal, "failed to list identity providers")
	}

	var filteredInstances []*api.MyIdentityProvidersListEntry
	for _, idp := range idps {
		alias := ""
		if idp.Alias != nil {
			alias = *idp.Alias
		}

		displayName := ""
		if idp.DisplayName != nil {
			displayName = *idp.DisplayName
		}

		providerID := ""
		if idp.ProviderID != nil {
			providerID = *idp.ProviderID
		}

		enabled := false
		if idp.Enabled != nil {
			enabled = *idp.Enabled
		}

		// Convert provider ID to our enum
		var providerType api.IdentityProviderDefs_Type
		switch providerID {
		case "google":
			providerType = api.IdentityProviderDefs_Google
		case "microsoft":
			providerType = api.IdentityProviderDefs_Microsoft
		default:
			continue // Skip unsupported providers
		}

		// Filter by provider type
		if req.Type != nil {
			if providerType != *req.Type {
				continue
			}
		}

		// Filter by enabled status
		if req.Enabled != nil {
			if enabled != *req.Enabled {
				continue
			}
		}

		// Get creation metadata from config
		var created int64
		if idp.Config != nil {
			if createdAtStr, exists := (*idp.Config)["createdAt"]; exists {
				if createdAtInt, err := strconv.ParseInt(createdAtStr, 10, 64); err == nil {
					created = createdAtInt
				}
			}
		}

		filteredInstances = append(filteredInstances, &api.MyIdentityProvidersListEntry{
			Key:      alias,
			DispName: displayName,
			Type:     providerType,
			Enabled:  enabled,
			Created:  created,
		})
	}

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

	token, err := s.client.GetAccessToken()
	if err != nil {
		log.Printf("failed to get access token: %s", err)
		return nil, status.Error(codes.Internal, "authentication failed")
	}

	// Get identity provider from Keycloak
	idp, err := s.client.GetIdentityProvider(ctx, token, authInfo.Realm, req.Key)
	if err != nil {
		log.Printf("failed to get identity provider '%s': %s", req.Key, err)
		return nil, status.Errorf(codes.NotFound, "identity provider '%s' not found", req.Key)
	}

	alias := ""
	if idp.Alias != nil {
		alias = *idp.Alias
	}

	displayName := ""
	if idp.DisplayName != nil {
		displayName = *idp.DisplayName
	}

	providerID := ""
	if idp.ProviderID != nil {
		providerID = *idp.ProviderID
	}

	enabled := false
	if idp.Enabled != nil {
		enabled = *idp.Enabled
	}

	// Get configuration from Keycloak and populate response based on provider type
	config := make(map[string]string)
	if idp.Config != nil {
		config = *idp.Config
	}

	// Extract creation metadata from config
	var created int64
	var createdBy string
	if createdAtStr, exists := config["createdAt"]; exists {
		if createdAtInt, err := strconv.ParseInt(createdAtStr, 10, 64); err == nil {
			created = createdAtInt
		}
	}
	if cb, exists := config["createdBy"]; exists {
		createdBy = cb
	}

	resp := &api.MyIdentityProviderGetResp{
		Key:       alias,
		DispName:  displayName,
		Enabled:   enabled,
		Created:   created,
		CreatedBy: createdBy,
	}

	// Get configuration from Keycloak and populate response based on provider type

	switch providerID {
	case "google":
		resp.Type = api.IdentityProviderDefs_Google
		clientID := config["clientId"]
		clientSecret := config["clientSecret"]
		hostedDomain := config["hostedDomain"]

		resp.Google = &api.GoogleIDPConfig{
			ClientId:     clientID,
			ClientSecret: clientSecret,
			HostedDomain: hostedDomain,
		}

	case "microsoft":
		resp.Type = api.IdentityProviderDefs_Microsoft
		clientID := config["clientId"]
		clientSecret := config["clientSecret"]
		tenantID := config["tenantId"] // Will be empty string if not set

		resp.Microsoft = &api.MicrosoftIDPConfig{
			ClientId:     clientID,
			ClientSecret: clientSecret,
			TenantId:     tenantID,
		}

	default:
		return nil, status.Errorf(codes.InvalidArgument, "unsupported provider type: %s", providerID)
	}

	return resp, nil
}

func (s *MyTenantServer) UpdateMyIdentityProvider(ctx context.Context, req *api.MyIdentityProviderUpdateReq) (*api.MyIdentityProviderUpdateResp, error) {
	authInfo, _ := auth.GetAuthInfoFromContext(ctx)
	if authInfo == nil {
		return nil, status.Error(codes.Unauthenticated, "authentication required")
	}

	if strings.TrimSpace(req.Key) == "" {
		return nil, status.Error(codes.InvalidArgument, "identity provider key is required")
	}

	// validate key format (should match creation validation)
	keyRegex := regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)
	if !keyRegex.MatchString(req.Key) {
		return nil, status.Error(codes.InvalidArgument, "identity provider key must contain only alphanumeric characters, hyphens, and underscores")
	}

	// handle display name validation
	displayName := strings.TrimSpace(req.DispName)
	if displayName == "" {
		displayName = req.Key
	}

	// display name length limit check
	if len(displayName) > 30 {
		return nil, status.Error(codes.InvalidArgument, "display name must not exceed 30 characters")
	}

	token, err := s.client.GetAccessToken()
	if err != nil {
		log.Printf("failed to get access token: %s", err)
		return nil, status.Error(codes.Internal, "authentication failed")
	}

	// Check if provider exists and get its type
	idp, err := s.client.GetIdentityProvider(ctx, token, authInfo.Realm, req.Key)
	if err != nil {
		log.Printf("failed to get identity provider '%s': %s", req.Key, err)
		return nil, status.Errorf(codes.NotFound, "identity provider '%s' not found", req.Key)
	}

	// Get existing configuration to preserve creation metadata
	existingConfig := make(map[string]string)
	if idp.Config != nil {
		existingConfig = *idp.Config
	}

	// Define handler map for different provider types
	updateHandlers := map[api.IdentityProviderDefs_Type]func() error{
		api.IdentityProviderDefs_Google: func() error {
			if req.Google == nil {
				return status.Error(codes.InvalidArgument, "Google configuration is required")
			}
			if req.Google.ClientId == "" || req.Google.ClientSecret == "" {
				return status.Error(codes.InvalidArgument, "Google client ID and secret are required")
			}

			// validate Google client ID format (should end with .googleusercontent.com)
			if !strings.HasSuffix(req.Google.ClientId, ".googleusercontent.com") {
				return status.Error(codes.InvalidArgument, "Google client ID must end with .googleusercontent.com")
			}

			// validate hosted domain format if provided
			if req.Google.HostedDomain != "" {
				domainRegex := regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9]*\.([a-zA-Z]{2,})+$`)
				if !domainRegex.MatchString(req.Google.HostedDomain) {
					return status.Error(codes.InvalidArgument, "hosted domain must be a valid domain name")
				}
			}

			// Build Google IDP configuration
			idpConfig := map[string]string{
				"clientId":     req.Google.ClientId,
				"clientSecret": req.Google.ClientSecret,
			}

			if req.Google.HostedDomain != "" {
				idpConfig["hostedDomain"] = req.Google.HostedDomain
			}

			// Preserve creation metadata
			if createdAt, exists := existingConfig["createdAt"]; exists {
				idpConfig["createdAt"] = createdAt
			}
			if createdBy, exists := existingConfig["createdBy"]; exists {
				idpConfig["createdBy"] = createdBy
			}

			idpRep := gocloak.IdentityProviderRepresentation{
				Alias:       &req.Key,
				DisplayName: &displayName,
				ProviderID:  gocloak.StringP("google"),
				Enabled:     &req.Enabled,
				Config:      &idpConfig,
			}

			err = s.client.UpdateIdentityProvider(ctx, token, authInfo.Realm, req.Key, idpRep)
			if err != nil {
				log.Printf("failed to update Google identity provider: %s", err)
				return status.Error(codes.Internal, "failed to update identity provider")
			}
			return nil
		},

		api.IdentityProviderDefs_Microsoft: func() error {
			if req.Microsoft == nil {
				return status.Error(codes.InvalidArgument, "Microsoft configuration is required")
			}
			if req.Microsoft.ClientId == "" || req.Microsoft.ClientSecret == "" {
				return status.Error(codes.InvalidArgument, "Microsoft client ID and secret are required")
			}

			// Validate Microsoft client ID format (should be a valid GUID)
			guidPattern := regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
			if !guidPattern.MatchString(req.Microsoft.ClientId) {
				return status.Error(codes.InvalidArgument, "Microsoft client ID must be a valid GUID")
			}

			// Validate tenant ID if provided
			if req.Microsoft.TenantId != "" {
				// Tenant ID can be a GUID, domain name, or special Azure AD values
				isSpecialValue := req.Microsoft.TenantId == "common" || req.Microsoft.TenantId == "organizations" || req.Microsoft.TenantId == "consumers"
				isGUID := guidPattern.MatchString(req.Microsoft.TenantId)

				if !isSpecialValue && !isGUID {
					// Check if it's a valid domain name
					domainPattern := regexp.MustCompile(`^([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$`)
					if !domainPattern.MatchString(req.Microsoft.TenantId) {
						return status.Error(codes.InvalidArgument, "Microsoft tenant ID must be a valid GUID, domain name, or one of: common, organizations, consumers")
					}
				}
			}

			// Build Microsoft IDP configuration
			idpConfig := map[string]string{
				"clientId":     req.Microsoft.ClientId,
				"clientSecret": req.Microsoft.ClientSecret,
			}

			if req.Microsoft.TenantId != "" {
				idpConfig["tenantId"] = req.Microsoft.TenantId
			}

			// Preserve creation metadata
			if createdAt, exists := existingConfig["createdAt"]; exists {
				idpConfig["createdAt"] = createdAt
			}
			if createdBy, exists := existingConfig["createdBy"]; exists {
				idpConfig["createdBy"] = createdBy
			}

			idpRep := gocloak.IdentityProviderRepresentation{
				Alias:       &req.Key,
				DisplayName: &displayName,
				ProviderID:  gocloak.StringP("microsoft"),
				Enabled:     &req.Enabled,
				Config:      &idpConfig,
			}

			err = s.client.UpdateIdentityProvider(ctx, token, authInfo.Realm, req.Key, idpRep)
			if err != nil {
				log.Printf("failed to update Microsoft identity provider: %s", err)
				return status.Error(codes.Internal, "failed to update identity provider")
			}
			return nil
		},
	}

	// Update identity provider using handler map
	handler, exists := updateHandlers[req.Type]
	if !exists {
		return nil, status.Error(codes.InvalidArgument, "unsupported provider type")
	}

	if err := handler(); err != nil {
		return nil, err
	}

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

	token, err := s.client.GetAccessToken()
	if err != nil {
		log.Printf("failed to get access token: %s", err)
		return nil, status.Error(codes.Internal, "authentication failed")
	}

	// Check if provider exists before deleting
	_, err = s.client.GetIdentityProvider(ctx, token, authInfo.Realm, req.Key)
	if err != nil {
		log.Printf("failed to get identity provider '%s': %s", req.Key, err)
		return nil, status.Errorf(codes.NotFound, "identity provider '%s' not found", req.Key)
	}

	// Delete the identity provider
	err = s.client.DeleteIdentityProvider(ctx, token, authInfo.Realm, req.Key)
	if err != nil {
		log.Printf("failed to delete identity provider '%s': %s", req.Key, err)
		return nil, status.Error(codes.Internal, "failed to delete identity provider")
	}

	return &api.MyIdentityProviderDeleteResp{}, nil
}

// Helper methods for Identity Provider Management

func NewMyTenantServer(ctx *model.GrpcServerContext, client *keycloak.Client, ep string) *MyTenantServer {
	srv := &MyTenantServer{
		client: client,
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
