// Copyright © 2025 Prabhjot Singh Sethi, All Rights reserved
// Author: Prabhjot Singh Sethi <prabhjot.sethi@gmail.com>

package server

import (
	"context"
	"log"
	"strconv"

	"github.com/Nerzal/gocloak/v13"
	"github.com/Prabhjot-Sethi/auth-gateway/api"
	"github.com/Prabhjot-Sethi/auth-gateway/pkg/keycloak"
	"github.com/Prabhjot-Sethi/auth-gateway/pkg/model"
	"github.com/Prabhjot-Sethi/auth-gateway/pkg/table"
	"github.com/Prabhjot-Sethi/core/errors"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type UserApiServer struct {
	api.UnimplementedUserServer
	tenantTbl *table.TenantTable
	client    *keycloak.Client
}

func (s *UserApiServer) GetUsers(ctx context.Context, req *api.UsersListReq) (*api.UsersListResp, error) {
	tKey := table.TenantKey{
		Name: req.Tenant,
	}

	tEntry := &table.TenantEntry{}
	err := s.tenantTbl.Find(ctx, &tKey, tEntry)
	if err != nil {
		log.Printf("failed to find the tenant entry: %s", err)
		if errors.IsNotFound(err) {
			return nil, status.Errorf(codes.NotFound, "Tenant %s not found", req.Tenant)
		}
		return nil, status.Errorf(codes.Internal, "Somthing went wrong, Please try again later")
	}

	if tEntry.KCStatus == nil || tEntry.KCStatus.RealmName == "" {
		return nil, status.Errorf(codes.Unavailable, "Tenant %s setup not completed", req.Tenant)
	}

	token, _ := s.client.GetAccessToken()
	limit := req.Limit
	if limit == 0 {
		limit = 10
	}
	params := gocloak.GetUsersParams{
		First:  gocloak.IntP(int(req.Offset)),
		Max:    gocloak.IntP(int(limit)),
		Search: gocloak.StringP(req.Search),
	}
	count, err := s.client.GetUserCount(ctx, token, tEntry.KCStatus.RealmName, params)
	if err != nil {
		log.Printf("failed to get users count: %s", err)
		return nil, status.Errorf(codes.Internal, "Somthing went wrong, Please try again later")
	}

	users, err := s.client.GetUsers(ctx, token, tEntry.KCStatus.RealmName, params)
	if err != nil {
		log.Printf("failed to get users list: %s", err)
		return nil, status.Errorf(codes.Internal, "Somthing went wrong, Please try again later")
	}

	resp := &api.UsersListResp{
		Count: int32(count),
		Items: []*api.UserListEntry{},
	}

	for _, user := range users {
		username := ""
		if user.Username != nil {
			username = *user.Username
		}
		email := ""
		if user.Email != nil {
			email = *user.Email
		}
		firstName := ""
		if user.FirstName != nil {
			firstName = *user.FirstName
		}
		lastName := ""
		if user.LastName != nil {
			lastName = *user.LastName
		}
		enabled := false
		if user.Enabled != nil {
			enabled = *user.Enabled
		}
		createTime := int64(0)
		if user.CreatedTimestamp != nil {
			createTime = *user.CreatedTimestamp
		}
		lastAccess := int64(0)
		if user.Attributes != nil {
			if val, ok := (*user.Attributes)["LastAccess"]; ok && len(val) != 0 {
				i, err := strconv.ParseInt(val[0], 10, 64)
				if err != nil {
					log.Println("failed to fetch last access timestamp, invalid value", val)
				} else {
					lastAccess = i
				}
			}
		}
		item := &api.UserListEntry{
			Username:          username,
			Email:             email,
			FirstName:         firstName,
			LastName:          lastName,
			Enabled:           enabled,
			CreationTimestamp: createTime / 1000,
			LastAccess:        lastAccess,
		}
		resp.Items = append(resp.Items, item)
	}

	return resp, nil
}

func NewUserServer(ctx *model.GrpcServerContext, client *keycloak.Client) *UserApiServer {
	tbl, err := table.GetTenantTable()
	if err != nil {
		log.Panicf("failed to get tenant table: %s", err)
	}
	srv := &UserApiServer{
		tenantTbl: tbl,
		client:    client,
	}
	api.RegisterUserServer(ctx.Server, srv)
	err = api.RegisterUserHandler(context.Background(), ctx.Mux, ctx.Conn)
	if err != nil {
		log.Panicf("failed to register handler: %s", err)
	}
	return srv
}
