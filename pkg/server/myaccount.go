// Copyright © 2025 Prabhjot Singh Sethi, All Rights reserved
// Author: Prabhjot Singh Sethi <prabhjot.sethi@gmail.com>

package server

import (
	"context"
	"log"
	"time"

	"github.com/Prabhjot-Sethi/auth-gateway/api"
	"github.com/Prabhjot-Sethi/auth-gateway/pkg/model"
	"github.com/Prabhjot-Sethi/core/auth"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// MyAccountServer implements the api.MyAccountServer interface.
type MyAccountServer struct {
	api.UnimplementedMyAccountServer
}

// GetMyInfo returns account information for the current user.
// If authentication info is missing from the context, it returns an Unauthenticated error.
//
// Parameters:
//
//	ctx - request context
//	req - request message containing any required parameters
//
// Returns:
//
//	*api.MyInfoGetResp - response with user info (username and full name)
//	error - gRPC error if unauthenticated, otherwise nil
func (s *MyAccountServer) GetMyInfo(ctx context.Context, req *api.MyInfoGetReq) (*api.MyInfoGetResp, error) {
	authInfo, _ := auth.GetAuthInfoFromContext(ctx)
	if authInfo == nil {
		return nil, status.Errorf(codes.Unauthenticated, "User not authenticated")
	}
	return &api.MyInfoGetResp{
		Username: authInfo.UserName, // Use username from auth info
		FullName: authInfo.Email,    // Use email as full name
	}, nil
}

// CreateApiKey returns a dummy API key entry for the user.
//
// Parameters:
//
//	ctx - request context
//	req - request message containing API key creation parameters
//
// Returns:
//
//	*api.ApiKeyCreateResp - response with dummy API key details
//	error - always nil in this stub
func (s *MyAccountServer) CreateApiKey(ctx context.Context, req *api.ApiKeyCreateReq) (*api.ApiKeyCreateResp, error) {
	return &api.ApiKeyCreateResp{
		Name:       "dummy-api-key",       // Dummy API key name
		Id:         "dummy-key-id",        // Dummy API key ID
		Status:     api.ApiKeyDef_Active,  // Dummy status (active)
		LastUsed:   time.Now().Unix(),     // Current Unix timestamp as last used
		CreateTime: 1716800000,            // Dummy creation timestamp
		ExpireAt:   0,                     // No expiration
		Secret:     "mydummysecretkey123", // Dummy secret
	}, nil
}

// DisableApiKey returns a dummy response for disabling an API key.
//
// Parameters:
//
//	ctx - request context
//	req - request message containing the API key ID to disable
//
// Returns:
//
//	*api.ApiKeyDisableResp - empty response (dummy)
//	error - always nil in this stub
func (s *MyAccountServer) DisableApiKey(ctx context.Context, req *api.ApiKeyDisableReq) (*api.ApiKeyDisableResp, error) {
	return &api.ApiKeyDisableResp{}, nil
}

// EnableApiKey returns a dummy response for enabling an API key.
//
// Parameters:
//
//	ctx - request context
//	req - request message containing the API key ID to enable
//
// Returns:
//
//	*api.ApiKeyEnableResp - empty response (dummy)
//	error - always nil in this stub
func (s *MyAccountServer) EnableApiKey(ctx context.Context, req *api.ApiKeyEnableReq) (*api.ApiKeyEnableResp, error) {
	return &api.ApiKeyEnableResp{}, nil
}

// DeleteApiKey returns a dummy response for deleting an API key.
//
// Parameters:
//
//	ctx - request context
//	req - request message containing the API key ID to delete
//
// Returns:
//
//	*api.ApiKeyDeleteResp - empty response (dummy)
//	error - always nil in this stub
func (s *MyAccountServer) DeleteApiKey(ctx context.Context, req *api.ApiKeyDeleteReq) (*api.ApiKeyDeleteResp, error) {
	return &api.ApiKeyDeleteResp{}, nil
}

// ListApiKeys returns a list of dummy API keys for the user.
//
// Parameters:
//
//	ctx - request context
//	req - request message (unused in this stub)
//
// Returns:
//
//	*api.ApiKeysListResp - response containing a list of dummy API keys
//	error - always nil in this stub
func (s *MyAccountServer) ListApiKeys(ctx context.Context, req *api.ApiKeysListReq) (*api.ApiKeysListResp, error) {
	return &api.ApiKeysListResp{
		Items: []*api.ApiKeyListEntry{
			{
				Name:       "dummy-api-key",      // Dummy API key name
				Id:         "dummy-key-id",       // Dummy API key ID
				Status:     api.ApiKeyDef_Active, // Dummy status (active)
				LastUsed:   time.Now().Unix(),    // Current Unix timestamp as last used
				CreateTime: 1716800000,           // Dummy creation timestamp
				ExpireAt:   0,                    // No expiration
			},
			{
				Name:       "dummy-api-key-2",         // Second dummy API key name
				Id:         "dummy-key-id-2",          // Second dummy API key ID
				Status:     api.ApiKeyDef_Active,      // Dummy status (active)
				LastUsed:   time.Now().Unix() - 3600,  // Last used 1 hour ago
				CreateTime: 1716801000,                // Dummy creation timestamp
				ExpireAt:   time.Now().Unix() + 86400, // Expires in 1 day
			},
		},
	}, nil
}

// NewMyAccountServer registers and returns a new MyAccountServer instance.
//
// Parameters:
//
//	ctx - pointer to GrpcServerContext containing gRPC server, mux, and connection
//
// Returns:
//
//	*MyAccountServer - the registered server instance
func NewMyAccountServer(ctx *model.GrpcServerContext) *MyAccountServer {
	srv := &MyAccountServer{}
	api.RegisterMyAccountServer(ctx.Server, srv)
	err := api.RegisterMyAccountHandler(context.Background(), ctx.Mux, ctx.Conn)
	if err != nil {
		log.Panicf("failed to register handler: %s", err)
	}
	return srv
}
