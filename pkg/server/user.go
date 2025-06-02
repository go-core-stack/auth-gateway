// Copyright © 2025 Prabhjot Singh Sethi, All Rights reserved
// Author: Prabhjot Singh Sethi <prabhjot.sethi@gmail.com>

package server

import (
	"context"
	"log"
	"strings"
	"time"

	"github.com/Nerzal/gocloak/v13"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	auth "github.com/go-core-stack/auth/context"
	"github.com/go-core-stack/core/errors"
	"github.com/go-core-stack/core/utils"

	"github.com/Prabhjot-Sethi/auth-gateway/api"
	"github.com/Prabhjot-Sethi/auth-gateway/pkg/keycloak"
	"github.com/Prabhjot-Sethi/auth-gateway/pkg/model"
	"github.com/Prabhjot-Sethi/auth-gateway/pkg/table"
)

type UserApiServer struct {
	api.UnimplementedUserServer
	tenantTbl *table.TenantTable
	userTbl   *table.UserTable
	client    *keycloak.Client
}

func (s *UserApiServer) getTenant(ctx context.Context, name string) (*table.TenantEntry, error) {
	tKey := table.TenantKey{
		Name: name,
	}

	tEntry, err := s.tenantTbl.Find(ctx, &tKey)
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
	_, err := auth.GetAuthInfoFromContext(ctx)
	if err != nil {
		return nil, status.Errorf(codes.Unauthenticated, "Authentication required: %s", err.Error())
	}

	count, err := s.userTbl.CountByTenant(ctx, req.Tenant)
	if err != nil {
		log.Printf("failed to count users for tenant %s: %s", req.Tenant, err)
		return nil, status.Errorf(codes.Internal, "Something went wrong, Please try again later")
	}
	resp := &api.UsersListResp{
		Count: int32(count),
		Items: []*api.UserListEntry{},
	}

	users, err := s.userTbl.GetByTenant(ctx, req.Tenant, int64(req.Offset), int64(req.Limit))
	if err != nil && !errors.IsNotFound(err) {
		log.Printf("failed to fetch users for tenant %s: %s", req.Tenant, err)
		return nil, status.Errorf(codes.Internal, "Something went wrong, Please try again later")
	}
	for _, user := range users {
		item := &api.UserListEntry{
			Username:          user.Key.Username,
			Email:             user.Info.Email,
			FirstName:         user.Info.FirstName,
			LastName:          user.Info.LastName,
			Enabled:           !utils.PBool(user.Disabled),
			CreationTimestamp: user.Created,
			LastAccess:        user.LastAccess,
		}
		resp.Items = append(resp.Items, item)
	}

	return resp, nil
}

func (s *UserApiServer) CreateUser(ctx context.Context, req *api.UserCreateReq) (*api.UserCreateResp, error) {
	_, err := s.getTenant(ctx, req.Tenant)
	if err != nil {
		return nil, err
	}
	now := time.Now().Unix()
	uEntry := &table.UserEntry{
		Key: &table.UserKey{
			Tenant:   req.Tenant,
			Username: req.Username,
		},
		Info: &table.UserInfo{
			FirstName: req.Firstname,
			LastName:  req.Lastname,
			Email:     req.Email,
		},
		Created:  now,
		Updated:  now,
		Disabled: gocloak.BoolP(req.Disabled),
	}
	if req.Password != "" {
		uEntry.Password = &table.UserTempPassword{
			Value: req.Password,
		}
	}
	err = s.userTbl.Insert(ctx, uEntry.Key, uEntry)
	if err != nil {
		if !errors.IsAlreadyExists(err) {
			return nil, status.Errorf(codes.InvalidArgument, "failed to create user: %s", err.Error())
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

func (s *UserApiServer) GetUser(ctx context.Context, req *api.UserGetReq) (*api.UserGetResp, error) {
	uKey := &table.UserKey{
		Tenant:   req.Tenant,
		Username: req.Username,
	}
	uEntry, err := s.userTbl.Find(ctx, uKey)
	if err != nil {
		if errors.IsNotFound(err) {
			return nil, status.Errorf(codes.NotFound, "User %s not found in tenant %s", req.Username, req.Tenant)
		}
		log.Printf("failed to find user entry: %s", err)
		return nil, status.Errorf(codes.Internal, "Something went wrong, Please try again later")
	}

	resp := &api.UserGetResp{
		Username:          uEntry.Key.Username,
		Email:             uEntry.Info.Email,
		FirstName:         uEntry.Info.FirstName,
		LastName:          uEntry.Info.LastName,
		Enabled:           !utils.PBool(uEntry.Disabled),
		CreationTimestamp: uEntry.Created,
		LastAccess:        uEntry.LastAccess,
	}
	return resp, nil
}

func (s *UserApiServer) EnableUser(ctx context.Context, req *api.UserEnableReq) (*api.UserEnableResp, error) {
	tEntry, err := s.getTenant(ctx, req.Tenant)
	if err != nil {
		return nil, err
	}

	if tEntry.Config.DefaultAdmin.UserID == req.Username {
		return nil, status.Errorf(codes.PermissionDenied, "Default Tenant Admin cannot be enabled/disabled")
	}

	update := &table.UserEntry{
		Key: &table.UserKey{
			Tenant:   req.Tenant,
			Username: req.Username,
		},
		Updated:  time.Now().Unix(),
		Disabled: gocloak.BoolP(false),
	}
	err = s.userTbl.Update(ctx, update.Key, update)
	if err != nil {
		log.Printf("failed to update user entry: %s", err)
		return nil, status.Errorf(codes.Internal, "Something went wrong, Please try again later")
	}

	return &api.UserEnableResp{}, nil
}

func (s *UserApiServer) DisableUser(ctx context.Context, req *api.UserDisableReq) (*api.UserDisableResp, error) {
	tEntry, err := s.getTenant(ctx, req.Tenant)
	if err != nil {
		return nil, err
	}

	if tEntry.Config.DefaultAdmin.UserID == req.Username {
		return nil, status.Errorf(codes.PermissionDenied, "Default Tenant Admin cannot be enabled/disabled")
	}

	update := &table.UserEntry{
		Key: &table.UserKey{
			Tenant:   req.Tenant,
			Username: req.Username,
		},
		Updated:  time.Now().Unix(),
		Disabled: gocloak.BoolP(true),
	}
	err = s.userTbl.Update(ctx, update.Key, update)
	if err != nil {
		log.Printf("failed to update user entry: %s", err)
		return nil, status.Errorf(codes.Internal, "Something went wrong, Please try again later")
	}

	return &api.UserDisableResp{}, nil
}

func (s *UserApiServer) UpdateUser(ctx context.Context, req *api.UserUpdateReq) (*api.UserUpdateResp, error) {
	tEntry, err := s.getTenant(ctx, req.Tenant)
	if err != nil {
		return nil, err
	}

	if tEntry.Config.DefaultAdmin.UserID == req.Username {
		return nil, status.Errorf(codes.PermissionDenied, "Default Tenant Admin cannot be updated")
	}

	update := &table.UserEntry{
		Key: &table.UserKey{
			Tenant:   req.Tenant,
			Username: req.Username,
		},
		Info: &table.UserInfo{
			FirstName: req.Firstname,
			LastName:  req.Lastname,
			Email:     req.Email,
		},
		Updated:  time.Now().Unix(),
		Disabled: utils.BoolP(req.Disabled),
	}
	err = s.userTbl.Update(ctx, update.Key, update)
	if err != nil {
		if errors.IsNotFound(err) {
			return nil, status.Errorf(codes.NotFound, "User %s not found in tenant %s", req.Username, req.Tenant)
		}
		log.Printf("failed to update user entry: %s", err)
		return nil, status.Errorf(codes.Internal, "Something went wrong, Please try again later")
	}

	resp := &api.UserUpdateResp{
		Username:  update.Key.Username,
		Email:     update.Info.Email,
		FirstName: update.Info.FirstName,
		LastName:  update.Info.LastName,
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

	now := time.Now().Unix()
	uEntry := &table.UserEntry{
		Key: &table.UserKey{
			Tenant:   req.Tenant,
			Username: req.Username,
		},
		Updated: now,
		Deleted: gocloak.BoolP(true),
	}
	err = s.userTbl.Update(ctx, uEntry.Key, uEntry)
	if err != nil {
		if !errors.IsAlreadyExists(err) {
			return nil, status.Errorf(codes.InvalidArgument, "failed to create user: %s", err.Error())
		}
	}

	return &api.UserDeleteResp{}, nil
}

func (s *UserApiServer) sessionsToApi(session *gocloak.UserSessionRepresentation) *api.UserSessionInfo {
	if session == nil {
		return nil
	}

	username := ""
	if session.Username != nil {
		username = *session.Username
	}

	sessionId := ""
	if session.ID != nil {
		sessionId = *session.ID
	}

	startTime := int64(0)
	if session.Start != nil {
		startTime = *session.Start
	}

	lastAccess := int64(0)
	if session.LastAccess != nil {
		lastAccess = *session.LastAccess
	}

	ipAddress := ""
	if session.IPAddress != nil {
		ipAddress = *session.IPAddress
	}

	return &api.UserSessionInfo{
		Username:   username,
		SessionId:  sessionId,
		Started:    startTime,
		LastAccess: lastAccess,
		Ip:         ipAddress,
	}
}
func (s *UserApiServer) ListUserSessions(ctx context.Context, req *api.UserSessionsListReq) (*api.UserSessionsListResp, error) {
	_, err := s.getTenant(ctx, req.Tenant)
	if err != nil {
		return nil, err
	}

	resp := &api.UserSessionsListResp{}

	token, _ := s.client.GetAccessToken()
	var sessions []*gocloak.UserSessionRepresentation
	if req.Username != "" {
		params := gocloak.GetUsersParams{
			Username: gocloak.StringP(req.Username),
		}
		users, err := s.client.GetUsers(ctx, token, req.Tenant, params)
		if err != nil || len(users) == 0 {
			log.Printf("failed to fetch users: %v, got error: %s", req, err)
			return nil, status.Errorf(codes.Internal, "Something went wrong, Please try again later")
		}
		// validate case-insensitive match for username
		if *users[0].Username != strings.ToLower(req.Username) {
			log.Printf("failed to find user: %v", req)
			return nil, status.Errorf(codes.Internal, "Something went wrong, Please try again later")
		}
		sessions, err = s.client.GetUserSessions(ctx, token, req.Tenant, *users[0].ID)
		if err != nil {
			log.Printf("failed to get sessions: %v, got error: %s", req, err)
			return nil, status.Errorf(codes.Internal, "Something went wrong, Please try again later")
		}
		resp.Count = int32(len(sessions))
	} else {
		clientsParams := gocloak.GetClientsParams{
			ClientID: gocloak.StringP("controller"),
		}
		clients, err := s.client.GetClients(ctx, token, req.Tenant, clientsParams)
		if err != nil {
			log.Printf("failed to clients for: %v, got error: %s", req, err)
			return nil, status.Errorf(codes.Internal, "Something went wrong, Please try again later")
		}

		clientID := *clients[0].ID
		count, err := s.client.GetClientUserSessionsCount(ctx, token, req.Tenant, clientID)
		if err != nil {
			log.Printf("failed to fetch user session count for %v, got error: %s", req, err)
			return nil, status.Errorf(codes.Internal, "Something went wrong, Please try again later")
		}

		params := gocloak.GetClientUserSessionsParams{
			First: gocloak.IntP(int(req.Offset)),
			Max:   gocloak.IntP(int(req.Limit)),
		}

		if req.Limit == 0 {
			// if limit is not specified mark max equal to the total count available
			params.Max = gocloak.IntP(count)
		}

		sessions, err = s.client.GetClientUserSessions(ctx, token, req.Tenant, clientID, params)
		if err != nil {
			log.Printf("failed to fetch user sessions for %v, got error: %s", req, err)
			return nil, status.Errorf(codes.Internal, "Something went wrong, Please try again later")
		}

		resp.Count = int32(count)
	}

	for _, session := range sessions {
		if session != nil {
			resp.Items = append(resp.Items, s.sessionsToApi(session))
		}
	}

	return resp, nil
}

func (s *UserApiServer) LogoutUserSession(ctx context.Context, req *api.UserSessionLogoutReq) (*api.UserSessionLogoutResp, error) {
	params := gocloak.GetUsersParams{
		Username: gocloak.StringP(req.Username),
	}
	token, _ := s.client.GetAccessToken()
	users, err := s.client.GetUsers(ctx, token, req.Tenant, params)
	if err != nil || len(users) == 0 {
		log.Printf("failed to fetch users: %v, got error: %s", req, err)
		return nil, status.Errorf(codes.Internal, "Something went wrong, Please try again later")
	}
	// validate exact match for username
	if *users[0].Username != req.Username {
		log.Printf("failed to find user: %v, got error: %s", req, err)
		return nil, status.Errorf(codes.Internal, "Something went wrong, Please try again later")
	}
	if req.SessionId == "" {
		err = s.client.LogoutAllSessions(ctx, token, req.Tenant, *users[0].ID)
		if err != nil {
			log.Printf("failed to close all sessions of user: %s, got error: %s", req.Username, err)
			return nil, status.Errorf(codes.Internal, "failed to logout user sessions %s", err.Error())
		}
	} else {
		err = s.client.LogoutUserSession(ctx, token, req.Tenant, req.SessionId)
		if err != nil {
			log.Printf("failed to close specified session of user: %v, got error %s", req, err)
			return nil, status.Errorf(codes.Internal, "failed to logout user session %s", err.Error())
		}
	}

	return &api.UserSessionLogoutResp{}, nil
}

func NewUserServer(ctx *model.GrpcServerContext, client *keycloak.Client) *UserApiServer {
	tbl, err := table.GetTenantTable()
	if err != nil {
		log.Panicf("failed to get tenant table: %s", err)
	}
	uTbl, err := table.GetUserTable()
	if err != nil {
		log.Panicf("failed to get user table: %s", err)
	}
	srv := &UserApiServer{
		tenantTbl: tbl,
		userTbl:   uTbl,
		client:    client,
	}
	api.RegisterUserServer(ctx.Server, srv)
	err = api.RegisterUserHandler(context.Background(), ctx.Mux, ctx.Conn)
	if err != nil {
		log.Panicf("failed to register handler: %s", err)
	}
	return srv
}
