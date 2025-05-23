// Copyright © 2025 Prabhjot Singh Sethi, All Rights reserved
// Author: Prabhjot Singh Sethi <prabhjot.sethi@gmail.com>

package server

import (
	"context"
	"log"
	"strconv"

	"github.com/Nerzal/gocloak/v13"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/Prabhjot-Sethi/core/auth"
	"github.com/Prabhjot-Sethi/core/errors"

	"github.com/Prabhjot-Sethi/auth-gateway/api"
	"github.com/Prabhjot-Sethi/auth-gateway/pkg/keycloak"
	"github.com/Prabhjot-Sethi/auth-gateway/pkg/model"
	"github.com/Prabhjot-Sethi/auth-gateway/pkg/table"
)

type UserApiServer struct {
	api.UnimplementedUserServer
	tenantTbl *table.TenantTable
	client    *keycloak.Client
}

func (s *UserApiServer) getTenant(ctx context.Context, name string) (*table.TenantEntry, error) {
	tKey := table.TenantKey{
		Name: name,
	}

	tEntry := &table.TenantEntry{}
	err := s.tenantTbl.Find(ctx, &tKey, tEntry)
	if err != nil {
		log.Printf("failed to find the tenant entry: %s", err)
		if errors.IsNotFound(err) {
			return nil, status.Errorf(codes.NotFound, "Tenant %s not found", name)
		}
		return nil, status.Errorf(codes.Internal, "Somthing went wrong, Please try again later")
	}

	if tEntry.KCStatus == nil || tEntry.KCStatus.RealmName == "" {
		return nil, status.Errorf(codes.Unavailable, "Tenant %s setup not completed", name)
	}
	return tEntry, nil
}

func (s *UserApiServer) GetUsers(ctx context.Context, req *api.UsersListReq) (*api.UsersListResp, error) {
	authInfo, _ := auth.GetAuthInfoFromContext(ctx)
	if authInfo != nil {
		log.Printf("got auth info %v", *authInfo)
	}
	tEntry, err := s.getTenant(ctx, req.Tenant)
	if err != nil {
		return nil, err
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

func (s *UserApiServer) CreateUser(ctx context.Context, req *api.UserCreateReq) (*api.UserCreateResp, error) {
	tEntry, err := s.getTenant(ctx, req.Tenant)
	if err != nil {
		return nil, err
	}
	enabled := !req.Disabled
	user := gocloak.User{
		FirstName: gocloak.StringP(req.Firstname),
		LastName:  gocloak.StringP(req.Lastname),
		Email:     gocloak.StringP(req.Email),
		Enabled:   gocloak.BoolP(enabled),
		Username:  gocloak.StringP(req.Username),
	}
	token, _ := s.client.GetAccessToken()
	userID, err := s.client.CreateUser(ctx, token, tEntry.KCStatus.RealmName, user)
	if err != nil {
		log.Printf("failed to create user for Tenant: %s, got error: %s", req.Tenant, err)
		if ok := keycloak.IsConflictError(err); ok {
			return nil, status.Errorf(codes.AlreadyExists, "user already exists")
		}
		return nil, status.Errorf(codes.InvalidArgument, "failed to create user: %s", err.Error())
	}
	user.ID = gocloak.StringP(userID)
	if req.Password != "" {
		err = s.client.SetPassword(ctx, token, userID, tEntry.KCStatus.RealmName, req.Password, true)
		if err != nil {
			log.Printf("failed to set user first login password in for user %s:%s, got error: %s", req.Tenant, req.Username, err)
			return nil, status.Errorf(codes.InvalidArgument, "failed to set user password %s", err.Error())
		}
	}

	resp := &api.UserCreateResp{
		Username:  req.Username,
		Email:     req.Email,
		FirstName: req.Firstname,
		LastName:  req.Lastname,
		Enabled:   !req.Disabled,
	}
	return resp, nil
}

func (s *UserApiServer) DeleteUser(ctx context.Context, req *api.UserDeleteReq) (*api.UserDeleteResp, error) {
	tEntry, err := s.getTenant(ctx, req.Tenant)
	if err != nil {
		return nil, err
	}

	if tEntry.Config.DefaultAdmin.UserID == req.Username {
		return nil, status.Errorf(codes.PermissionDenied, "Default Tenant Admin")
	}

	token, _ := s.client.GetAccessToken()
	params := gocloak.GetUsersParams{
		Username: gocloak.StringP(req.Username),
	}
	users, err := s.client.GetUsers(ctx, token, tEntry.KCStatus.RealmName, params)
	if err != nil || len(users) == 0 {
		log.Printf("failed to find the user in given tenant %s, got error: %s", req.Tenant, err)
		return nil, status.Errorf(codes.InvalidArgument, "user not found")
	}
	// assume that it is always the first and the only user in the list
	err = s.client.DeleteUser(ctx, token, tEntry.KCStatus.RealmName, *users[0].ID)
	if err != nil {
		log.Printf("failed to delete user %s:%s, got error: %s", req.Tenant, req.Username, err)
		return nil, status.Errorf(codes.InvalidArgument, "failed to delete user %s", err)
	}

	return &api.UserDeleteResp{}, nil
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
