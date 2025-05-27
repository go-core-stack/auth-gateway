// Copyright © 2025 Prabhjot Singh Sethi, All Rights reserved
// Author: Prabhjot Singh Sethi <prabhjot.sethi@gmail.com>

package server

import (
	"context"
	"log"
	"math/rand"
	"time"

	"github.com/Prabhjot-Sethi/auth-gateway/api"
	"github.com/Prabhjot-Sethi/auth-gateway/pkg/model"
	"github.com/Prabhjot-Sethi/auth-gateway/pkg/table"
	"github.com/Prabhjot-Sethi/core/auth"
	"github.com/Prabhjot-Sethi/core/errors"
	"github.com/Prabhjot-Sethi/core/utils"
	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

var (
	// character set used for generating secret key
	secretCharset = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/-")

	// minimum length of secret key
	secretKeyLength = 35
)

func generateSecret() string {
	// keep the length variable from 35 to 45
	l := rand.Intn(10)
	b := make([]rune, (secretKeyLength + l))
	for i := range b {
		b[i] = secretCharset[rand.Intn(len(secretCharset))]
	}
	return string(b)
}

// MyAccountServer implements the api.MyAccountServer interface.
type MyAccountServer struct {
	api.UnimplementedMyAccountServer
	apiKeys *table.ApiKeyTable // apiKeys table for managing API keys
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
		FullName: authInfo.FullName, // Use full name from auth info
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
	authInfo, _ := auth.GetAuthInfoFromContext(ctx)
	if authInfo == nil {
		return nil, status.Errorf(codes.Unauthenticated, "User not authenticated")
	}

	now := time.Now().Unix()
	uid := uuid.New().String() // Generate a new UUID for the API key ID
	apiKey := &table.ApiKeyEntry{
		Key: table.ApiKeyId{
			Id: uid,
		},
		Secret: &table.ApiKeySecret{
			Value: generateSecret(), // Generate a random secret key
		},
		UserInfo: &table.ApiKeyUserInfo{
			Tenant:   authInfo.Realm, // Use tenant from auth info
			Username: authInfo.UserName,
		},
		Created: now, // Set current time as creation time
		Config: &table.ApiKeyConfig{
			Name: req.Name, // Use the name from the request
		},
	}

	if req.Validity > 0 {
		apiKey.Config.ExpireAt = now + req.Validity // Set expiration time based on validity
	}

	err := s.apiKeys.Insert(ctx, &apiKey.Key, apiKey) // Add the API key to the table

	if err != nil {
		if errors.IsAlreadyExists(err) {
			return nil, status.Errorf(codes.Internal, "Failed to allocate api key id, try again in sometime")
		}
		log.Printf("got error while inserting apikey (%v): %s", apiKey, err)
		return nil, status.Errorf(codes.Internal, "Something went wrong, Please try again later")
	}

	return &api.ApiKeyCreateResp{
		Name:       req.Name,
		Id:         uid,
		Status:     api.ApiKeyDef_Active,
		CreateTime: now,
		ExpireAt:   apiKey.Config.ExpireAt,
		Secret:     apiKey.Secret.Value,
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
	authInfo, _ := auth.GetAuthInfoFromContext(ctx)
	if authInfo == nil {
		return nil, status.Errorf(codes.Unauthenticated, "User not authenticated")
	}
	user := &table.ApiKeyUserInfo{
		Tenant:   authInfo.Realm, // assuming tenant and realm are the same
		Username: authInfo.UserName,
	}
	found, err := s.apiKeys.FindIdByUser(ctx, req.Id, user)
	if err != nil {
		if errors.IsNotFound(err) {
			return nil, status.Errorf(codes.NotFound, "Api Key %s, not found", req.Id)
		}
		log.Printf("Error while fetching api key %s: %s", req.Id, err)
		return nil, status.Errorf(codes.Internal, "Something went wrong, Please try again later")
	}
	update := &table.ApiKeyEntry{
		Key:    found.Key,
		Config: found.Config,
	}
	update.Config.IsDisabled = utils.BoolP(true)

	err = s.apiKeys.Update(ctx, &update.Key, update)
	if err != nil {
		if errors.IsNotFound(err) {
			return nil, status.Errorf(codes.NotFound, "Api Key %s, not found", req.Id)
		}
		log.Printf("Error while Enabling api key %s: %s", req.Id, err)
		return nil, status.Errorf(codes.Internal, "Something went wrong, Please try again later")

	}
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
	authInfo, _ := auth.GetAuthInfoFromContext(ctx)
	if authInfo == nil {
		return nil, status.Errorf(codes.Unauthenticated, "User not authenticated")
	}
	user := &table.ApiKeyUserInfo{
		Tenant:   authInfo.Realm, // assuming tenant and realm are the same
		Username: authInfo.UserName,
	}
	found, err := s.apiKeys.FindIdByUser(ctx, req.Id, user)
	if err != nil {
		if errors.IsNotFound(err) {
			return nil, status.Errorf(codes.NotFound, "Api Key %s, not found", req.Id)
		}
		log.Printf("Error while fetching api key %s: %s", req.Id, err)
		return nil, status.Errorf(codes.Internal, "Something went wrong, Please try again later")
	}
	update := &table.ApiKeyEntry{
		Key:    found.Key,
		Config: found.Config,
	}
	update.Config.IsDisabled = utils.BoolP(false)

	err = s.apiKeys.Update(ctx, &update.Key, update)
	if err != nil {
		if errors.IsNotFound(err) {
			return nil, status.Errorf(codes.NotFound, "Api Key %s, not found", req.Id)
		}
		log.Printf("Error while Enabling api key %s: %s", req.Id, err)
		return nil, status.Errorf(codes.Internal, "Something went wrong, Please try again later")

	}
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
	authInfo, _ := auth.GetAuthInfoFromContext(ctx)
	if authInfo == nil {
		return nil, status.Errorf(codes.Unauthenticated, "User not authenticated")
	}
	user := &table.ApiKeyUserInfo{
		Tenant:   authInfo.Realm, // assuming tenant and realm are the same
		Username: authInfo.UserName,
	}
	err := s.apiKeys.DeleteIdByUser(ctx, req.Id, user)
	if err != nil {
		if errors.IsNotFound(err) {
			return nil, status.Errorf(codes.NotFound, "Api Key %s, not found", req.Id)
		}
		log.Printf("Error while deleting api key %s: %s", req.Id, err)
		return nil, status.Errorf(codes.Internal, "Something went wrong, Please try again later")
	}
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
	authInfo, _ := auth.GetAuthInfoFromContext(ctx)
	if authInfo == nil {
		return nil, status.Errorf(codes.Unauthenticated, "User not authenticated")
	}
	user := &table.ApiKeyUserInfo{
		Tenant:   authInfo.Realm, // assuming tenant and realm are the same
		Username: authInfo.UserName,
	}
	keys, err := s.apiKeys.FindByUser(ctx, user)
	if err != nil {
		if errors.IsNotFound(err) {
			return nil, status.Errorf(codes.NotFound, "No API keys found for user %s in tenant %s", user.Username, user.Tenant)
		}
		log.Printf("got error while fetching apikey list (%v): %s", user, err)
		return nil, status.Errorf(codes.Internal, "Something went wrong, Please try again later")
	}

	resp := &api.ApiKeysListResp{}
	for _, key := range keys {
		item := &api.ApiKeyListEntry{
			Id:         key.Key.Id,           // API key ID
			LastUsed:   key.LastUsed,         // Last used timestamp
			CreateTime: key.Created,          // Creation timestamp
			Status:     api.ApiKeyDef_Active, // Default status (active)
		}
		if key.Config != nil {
			item.Name = key.Config.Name         // Use the name from the API key config
			item.ExpireAt = key.Config.ExpireAt // Use the expiration time from the API key config
			if utils.PBool(key.Config.IsDisabled) {
				item.Status = api.ApiKeyDef_Disabled // Set status to disabled if the key is disabled
			} else if key.Config.ExpireAt != 0 && time.Now().Unix() >= key.Config.ExpireAt {
				item.Status = api.ApiKeyDef_Expired // Set status to expired if the current time exceeds expiration
			}
		}
		resp.Items = append(resp.Items, item) // Append the API key entry to the response
	}

	return resp, nil
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
	apiKeys, err := table.GetApiKeyTable()
	if err != nil {
		log.Panicf("failed to get API key table: %s", err)
	}
	srv := &MyAccountServer{
		apiKeys: apiKeys, // Initialize the API keys table
	}
	api.RegisterMyAccountServer(ctx.Server, srv)
	err = api.RegisterMyAccountHandler(context.Background(), ctx.Mux, ctx.Conn)
	if err != nil {
		log.Panicf("failed to register handler: %s", err)
	}
	return srv
}
