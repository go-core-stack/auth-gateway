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
	"github.com/go-core-stack/auth/route"
	"github.com/go-core-stack/core/errors"
	"github.com/go-core-stack/core/utils"

	"github.com/Prabhjot-Sethi/auth-gateway/api"
	"github.com/Prabhjot-Sethi/auth-gateway/pkg/keycloak"
	"github.com/Prabhjot-Sethi/auth-gateway/pkg/model"
	"github.com/Prabhjot-Sethi/auth-gateway/pkg/table"
)

type TenantUserApiServer struct {
	api.UnimplementedTenantUserServer
	tenantTbl *table.TenantTable
	userTbl   *table.UserTable
	client    *keycloak.Client
}

func (s *TenantUserApiServer) getTenant(ctx context.Context, name string) (*table.TenantEntry, error) {
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

func (s *TenantUserApiServer) GetUsers(ctx context.Context, req *api.TenantUsersListReq) (*api.TenantUsersListResp, error) {
	info, err := auth.GetAuthInfoFromContext(ctx)
	if err != nil {
		return nil, status.Errorf(codes.Unauthenticated, "Authentication required: %s", err.Error())
	}
	tenant := info.Realm

	count, err := s.userTbl.CountByTenant(ctx, tenant)
	if err != nil {
		log.Printf("failed to count users for tenant %s: %s", tenant, err)
		return nil, status.Errorf(codes.Internal, "Something went wrong, Please try again later")
	}
	resp := &api.TenantUsersListResp{
		Count: int32(count),
		Items: []*api.TenantUserListEntry{},
	}

	users, err := s.userTbl.GetByTenant(ctx, tenant, int64(req.Offset), int64(req.Limit))
	if err != nil && !errors.IsNotFound(err) {
		log.Printf("failed to fetch users for tenant %s: %s", tenant, err)
		return nil, status.Errorf(codes.Internal, "Something went wrong, Please try again later")
	}
	for _, user := range users {
		item := &api.TenantUserListEntry{
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

func (s *TenantUserApiServer) CreateUser(ctx context.Context, req *api.TenantUserCreateReq) (*api.TenantUserCreateResp, error) {
	info, err := auth.GetAuthInfoFromContext(ctx)
	if err != nil {
		return nil, status.Errorf(codes.Unauthenticated, "Authentication required: %s", err.Error())
	}
	tenant := info.Realm
	_, err = s.getTenant(ctx, tenant)
	if err != nil {
		return nil, err
	}
	now := time.Now().Unix()
	uEntry := &table.UserEntry{
		Key: &table.UserKey{
			Tenant:   tenant,
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

	resp := &api.TenantUserCreateResp{
		Username:  req.Username,
		Email:     req.Email,
		FirstName: req.Firstname,
		LastName:  req.Lastname,
		Enabled:   !req.Disabled,
	}
	return resp, nil
}

func (s *TenantUserApiServer) GetUser(ctx context.Context, req *api.TenantUserGetReq) (*api.TenantUserGetResp, error) {
	info, err := auth.GetAuthInfoFromContext(ctx)
	if err != nil {
		return nil, status.Errorf(codes.Unauthenticated, "Authentication required: %s", err.Error())
	}
	tenant := info.Realm
	uKey := &table.UserKey{
		Tenant:   tenant,
		Username: req.Username,
	}
	uEntry, err := s.userTbl.Find(ctx, uKey)
	if err != nil {
		if errors.IsNotFound(err) {
			return nil, status.Errorf(codes.NotFound, "User %s not found", req.Username)
		}
		log.Printf("failed to find user entry: %s", err)
		return nil, status.Errorf(codes.Internal, "Something went wrong, Please try again later")
	}

	resp := &api.TenantUserGetResp{
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

func (s *TenantUserApiServer) EnableUser(ctx context.Context, req *api.TenantUserEnableReq) (*api.TenantUserEnableResp, error) {
	info, err := auth.GetAuthInfoFromContext(ctx)
	if err != nil {
		return nil, status.Errorf(codes.Unauthenticated, "Authentication required: %s", err.Error())
	}
	tenant := info.Realm
	tEntry, err := s.getTenant(ctx, tenant)
	if err != nil {
		return nil, err
	}

	if tEntry.Config.DefaultAdmin.UserID == req.Username {
		return nil, status.Errorf(codes.PermissionDenied, "Default Tenant Admin cannot be enabled/disabled")
	}

	update := &table.UserEntry{
		Key: &table.UserKey{
			Tenant:   tenant,
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

	return &api.TenantUserEnableResp{}, nil
}

func (s *TenantUserApiServer) DisableUser(ctx context.Context, req *api.TenantUserDisableReq) (*api.TenantUserDisableResp, error) {
	info, err := auth.GetAuthInfoFromContext(ctx)
	if err != nil {
		return nil, status.Errorf(codes.Unauthenticated, "Authentication required: %s", err.Error())
	}
	tenant := info.Realm
	tEntry, err := s.getTenant(ctx, tenant)
	if err != nil {
		return nil, err
	}

	if tEntry.Config.DefaultAdmin.UserID == req.Username {
		return nil, status.Errorf(codes.PermissionDenied, "Default Tenant Admin cannot be enabled/disabled")
	}

	update := &table.UserEntry{
		Key: &table.UserKey{
			Tenant:   tenant,
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

	return &api.TenantUserDisableResp{}, nil
}

func (s *TenantUserApiServer) UpdateUser(ctx context.Context, req *api.TenantUserUpdateReq) (*api.TenantUserUpdateResp, error) {
	info, err := auth.GetAuthInfoFromContext(ctx)
	if err != nil {
		return nil, status.Errorf(codes.Unauthenticated, "Authentication required: %s", err.Error())
	}
	tenant := info.Realm
	tEntry, err := s.getTenant(ctx, tenant)
	if err != nil {
		return nil, err
	}

	if tEntry.Config.DefaultAdmin.UserID == req.Username {
		return nil, status.Errorf(codes.PermissionDenied, "Default Tenant Admin cannot be updated")
	}

	update := &table.UserEntry{
		Key: &table.UserKey{
			Tenant:   tenant,
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
			return nil, status.Errorf(codes.NotFound, "User %s not found in tenant %s", req.Username, tenant)
		}
		log.Printf("failed to update user entry: %s", err)
		return nil, status.Errorf(codes.Internal, "Something went wrong, Please try again later")
	}

	resp := &api.TenantUserUpdateResp{
		Username:  update.Key.Username,
		Email:     update.Info.Email,
		FirstName: update.Info.FirstName,
		LastName:  update.Info.LastName,
	}
	return resp, nil
}

func (s *TenantUserApiServer) DeleteUser(ctx context.Context, req *api.TenantUserDeleteReq) (*api.TenantUserDeleteResp, error) {
	info, err := auth.GetAuthInfoFromContext(ctx)
	if err != nil {
		return nil, status.Errorf(codes.Unauthenticated, "Authentication required: %s", err.Error())
	}
	tenant := info.Realm
	tEntry, err := s.getTenant(ctx, tenant)
	if err != nil {
		return nil, err
	}

	if tEntry.Config.DefaultAdmin.UserID == req.Username {
		return nil, status.Errorf(codes.PermissionDenied, "Default Tenant Admin")
	}

	now := time.Now().Unix()
	uEntry := &table.UserEntry{
		Key: &table.UserKey{
			Tenant:   tenant,
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

	return &api.TenantUserDeleteResp{}, nil
}

func (s *TenantUserApiServer) sessionsToApi(session *gocloak.UserSessionRepresentation) *api.TenantUserSessionInfo {
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

	return &api.TenantUserSessionInfo{
		Username:   username,
		SessionId:  sessionId,
		Started:    startTime,
		LastAccess: lastAccess,
		Ip:         ipAddress,
	}
}
func (s *TenantUserApiServer) ListUserSessions(ctx context.Context, req *api.TenantUserSessionsListReq) (*api.TenantUserSessionsListResp, error) {
	info, err := auth.GetAuthInfoFromContext(ctx)
	if err != nil {
		return nil, status.Errorf(codes.Unauthenticated, "Authentication required: %s", err.Error())
	}
	tenant := info.Realm
	_, err = s.getTenant(ctx, tenant)
	if err != nil {
		return nil, err
	}

	resp := &api.TenantUserSessionsListResp{}

	token, _ := s.client.GetAccessToken()
	var sessions []*gocloak.UserSessionRepresentation
	if req.Username != "" {
		params := gocloak.GetUsersParams{
			Username: gocloak.StringP(req.Username),
		}
		users, err := s.client.GetUsers(ctx, token, tenant, params)
		if err != nil || len(users) == 0 {
			log.Printf("failed to fetch users: %v, got error: %s", req, err)
			return nil, status.Errorf(codes.Internal, "Something went wrong, Please try again later")
		}
		// validate case-insensitive match for username
		if *users[0].Username != strings.ToLower(req.Username) {
			log.Printf("failed to find user: %v", req)
			return nil, status.Errorf(codes.Internal, "Something went wrong, Please try again later")
		}
		sessions, err = s.client.GetUserSessions(ctx, token, tenant, *users[0].ID)
		if err != nil {
			log.Printf("failed to get sessions: %v, got error: %s", req, err)
			return nil, status.Errorf(codes.Internal, "Something went wrong, Please try again later")
		}
		resp.Count = int32(len(sessions))
	} else {
		clientsParams := gocloak.GetClientsParams{
			ClientID: gocloak.StringP("controller"),
		}
		clients, err := s.client.GetClients(ctx, token, tenant, clientsParams)
		if err != nil {
			log.Printf("failed to clients for: %v, got error: %s", req, err)
			return nil, status.Errorf(codes.Internal, "Something went wrong, Please try again later")
		}

		clientID := *clients[0].ID
		count, err := s.client.GetClientUserSessionsCount(ctx, token, tenant, clientID)
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

		sessions, err = s.client.GetClientUserSessions(ctx, token, tenant, clientID, params)
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

func (s *TenantUserApiServer) LogoutUserSession(ctx context.Context, req *api.TenantUserSessionLogoutReq) (*api.TenantUserSessionLogoutResp, error) {
	info, err := auth.GetAuthInfoFromContext(ctx)
	if err != nil {
		return nil, status.Errorf(codes.Unauthenticated, "Authentication required: %s", err.Error())
	}
	tenant := info.Realm
	params := gocloak.GetUsersParams{
		Username: gocloak.StringP(req.Username),
	}
	token, _ := s.client.GetAccessToken()
	users, err := s.client.GetUsers(ctx, token, tenant, params)
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
		err = s.client.LogoutAllSessions(ctx, token, tenant, *users[0].ID)
		if err != nil {
			log.Printf("failed to close all sessions of user: %s, got error: %s", req.Username, err)
			return nil, status.Errorf(codes.Internal, "failed to logout user sessions %s", err.Error())
		}
	} else {
		err = s.client.LogoutUserSession(ctx, token, tenant, req.SessionId)
		if err != nil {
			log.Printf("failed to close specified session of user: %v, got error %s", req, err)
			return nil, status.Errorf(codes.Internal, "failed to logout user session %s", err.Error())
		}
	}

	return &api.TenantUserSessionLogoutResp{}, nil
}

func NewTenantUserServer(ctx *model.GrpcServerContext, client *keycloak.Client, ep string) *TenantUserApiServer {
	tbl, err := table.GetTenantTable()
	if err != nil {
		log.Panicf("failed to get tenant table: %s", err)
	}
	uTbl, err := table.GetUserTable()
	if err != nil {
		log.Panicf("failed to get user table: %s", err)
	}
	srv := &TenantUserApiServer{
		tenantTbl: tbl,
		userTbl:   uTbl,
		client:    client,
	}
	api.RegisterTenantUserServer(ctx.Server, srv)
	err = api.RegisterTenantUserHandler(context.Background(), ctx.Mux, ctx.Conn)
	if err != nil {
		log.Panicf("failed to register handler: %s", err)
	}
	routeTbl, err := route.GetRouteTable()
	if err != nil {
		log.Panicf("failed to get route table: %s", err)
	}
	for _, r := range api.RoutesTenantUser {
		key := &route.Key{
			Url:    r.Url,
			Method: r.Method,
		}
		entry := &route.Route{
			Key:      key,
			Endpoint: ep,
		}
		if err := routeTbl.Locate(context.Background(), key, entry); err != nil {
			log.Panicf("failed to register route %d %s: %s", r.Method, r.Url, err)
		}
	}
	return srv
}
