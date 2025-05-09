// Copyright © 2025 Prabhjot Singh Sethi, All Rights reserved
// Author: Prabhjot Singh Sethi <prabhjot.sethi@gmail.com>

package server

import (
	"context"
	"log"
	"time"

	"github.com/Prabhjot-Sethi/auth-gateway/api"
	"github.com/Prabhjot-Sethi/auth-gateway/pkg/model"
)

type UserApiServer struct {
	api.UnimplementedUserServer
}

func (s *UserApiServer) GetUsers(ctx context.Context, req *api.UsersListReq) (*api.UsersListResp, error) {
	log.Printf("fetching user list for tenant %s", req.Tenant)
	resp := &api.UsersListResp{
		Count: 2,
		Items: []*api.UserListEntry{
			{
				FirstName:         "Test",
				LastName:          "User",
				Username:          "test@example.com",
				Email:             "test@example.com",
				Enabled:           true,
				CreationTimestamp: time.Now().Unix() - 1100,
				LastAccess:        time.Now().Unix() - 90,
			},
			{
				FirstName:         "Test1",
				LastName:          "User",
				Username:          "test1@example.com",
				Email:             "test1@example.com",
				Enabled:           true,
				CreationTimestamp: time.Now().Unix() - 1000,
				LastAccess:        time.Now().Unix() - 100,
			},
		},
	}
	return resp, nil
}

func NewUserServer(ctx *model.GrpcServerContext) *UserApiServer {
	srv := &UserApiServer{}
	api.RegisterUserServer(ctx.Server, srv)
	err := api.RegisterUserHandler(context.Background(), ctx.Mux, ctx.Conn)
	if err != nil {
		log.Panicf("failed to register handler: %s", err)
	}
	return srv
}
