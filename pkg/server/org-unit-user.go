// Copyright © 2025 Prabhjot Singh Sethi, All Rights reserved
// Author: Prabhjot Singh Sethi <prabhjot.sethi@gmail.com>

package server

import (
	"context"
	"log"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	auth "github.com/go-core-stack/auth/context"
	"github.com/go-core-stack/auth/route"
	"github.com/go-core-stack/core/errors"

	"github.com/go-core-stack/auth-gateway/api"
	"github.com/go-core-stack/auth-gateway/pkg/model"
	"github.com/go-core-stack/auth-gateway/pkg/table"
)

type OrgUnitUserServer struct {
	api.UnimplementedOrgUnitUserServer
	tbl *table.OrgUnitUserTable
}

func (s *OrgUnitUserServer) ListOrgUnitUsers(ctx context.Context, req *api.OrgUnitUsersListReq) (*api.OrgUnitUsersListResp, error) {
	count, err := s.tbl.CountByOrgUnitId(ctx, req.Ou)
	if err != nil {
		log.Printf("failed to count org unit users, got error: %s", err)
		return nil, status.Errorf(codes.Internal, "Something went wrong, please try again later")
	}

	resp := &api.OrgUnitUsersListResp{
		Count: count,
	}

	list, err := s.tbl.GetByOrgUnitId(ctx, req.Ou, req.Offset, req.Limit)

	if err != nil && !errors.IsNotFound(err) {
		log.Printf("failed to get list of org unit users, got error: %s", err)
		return nil, status.Errorf(codes.Internal, "Something went wrong, please try again later")
	}

	for _, entry := range list {
		item := &api.OrgUnitUserListEntry{
			Username:  entry.Key.Username,
			Firstname: "Dummy Fist Name",
			Lastname:  "Dummy Last Name",
			Role:      entry.Role,
		}
		resp.Items = append(resp.Items, item)
	}

	return resp, nil
}

func (s *OrgUnitUserServer) AddOrgUnitUser(ctx context.Context, req *api.OrgUnitUserAddReq) (*api.OrgUnitUserAddResp, error) {
	authInfo, _ := auth.GetAuthInfoFromContext(ctx)
	if authInfo == nil {
		return nil, status.Errorf(codes.Unauthenticated, "User not authenticated")
	}

	// validate role, currently only admin, default and auditor roles are allowed
	if req.Role != "admin" && req.Role != "default" && req.Role != "auditor" {
		return nil, status.Errorf(codes.InvalidArgument, "Invalid role: %s", req.Role)
	}

	// TODO: validate if user exists, this might be never done to allow adding users
	// that are not yet logged in or registered with the system

	entry := &table.OrgUnitUser{
		Key: &table.OrgUnitUserKey{
			Tenant:    authInfo.Realm, // might require a better handling for across tenants access
			Username:  req.User,
			OrgUnitId: req.Ou,
		},
		Created:   time.Now().Unix(),
		CreatedBy: authInfo.UserName,
		Role:      req.Role,
	}

	err := s.tbl.Insert(ctx, entry.Key, entry)
	if err != nil {
		if errors.IsAlreadyExists(err) {
			return nil, status.Errorf(codes.AlreadyExists, "Org Unit User %s, already exists", req.User)
		}
		log.Printf("failed to add org unit user, got error: %s", err)
		return nil, status.Errorf(codes.Internal, "Something went wrong, please try again later")
	}

	return &api.OrgUnitUserAddResp{}, nil
}

func (s *OrgUnitUserServer) UpdateOrgUnitUser(ctx context.Context, req *api.OrgUnitUserUpdateReq) (*api.OrgUnitUserUpdateResp, error) {
	authInfo, _ := auth.GetAuthInfoFromContext(ctx)
	if authInfo == nil {
		return nil, status.Errorf(codes.Unauthenticated, "User not authenticated")
	}

	// validate role, currently only admin, default and auditor roles are allowed
	if req.Role != "admin" && req.Role != "default" && req.Role != "auditor" {
		return nil, status.Errorf(codes.InvalidArgument, "Invalid role: %s", req.Role)
	}

	update := &table.OrgUnitUser{
		Key: &table.OrgUnitUserKey{
			Tenant:    authInfo.Realm, // might require a better handling for across tenants access
			Username:  req.User,
			OrgUnitId: req.Ou,
		},
		Role: req.Role,
	}

	err := s.tbl.Update(ctx, update.Key, update)
	if err != nil {
		if errors.IsNotFound(err) {
			return nil, status.Errorf(codes.NotFound, "Org Unit User %s, not found", req.User)
		}
		log.Printf("failed to update org unit user, got error: %s", err)
		return nil, status.Errorf(codes.Internal, "Something went wrong, please try again later")
	}

	return &api.OrgUnitUserUpdateResp{}, nil
}
func (s *OrgUnitUserServer) DeleteOrgUnitUser(ctx context.Context, req *api.OrgUnitUserDeleteReq) (*api.OrgUnitUserDeleteResp, error) {
	authInfo, _ := auth.GetAuthInfoFromContext(ctx)
	if authInfo == nil {
		return nil, status.Errorf(codes.Unauthenticated, "User not authenticated")
	}

	key := &table.OrgUnitUserKey{
		Tenant:    authInfo.Realm, // might require a better handling for across tenants access
		Username:  req.User,
		OrgUnitId: req.Ou,
	}

	err := s.tbl.DeleteKey(ctx, key)
	if err != nil {
		if errors.IsNotFound(err) {
			return nil, status.Errorf(codes.NotFound, "Org Unit User %s, not found", req.User)
		}
		log.Printf("failed to delete org unit user, got error: %s", err)
		return nil, status.Errorf(codes.Internal, "Something went wrong, please try again later")
	}

	return &api.OrgUnitUserDeleteResp{}, nil
}

func NewOrgUnitUserServer(ctx *model.GrpcServerContext, ep string) *OrgUnitUserServer {
	tbl, err := table.GetOrgUnitUserTable()
	if err != nil {
		log.Panicf("failed to get org unit user table: %s", err)
	}
	srv := &OrgUnitUserServer{
		tbl: tbl,
	}
	api.RegisterOrgUnitUserServer(ctx.Server, srv)
	err = api.RegisterOrgUnitUserHandler(context.Background(), ctx.Mux, ctx.Conn)
	if err != nil {
		log.Panicf("failed to register handler: %s", err)
	}
	routeTbl, err := route.GetRouteTable()
	if err != nil {
		log.Panicf("failed to get route table: %s", err)
	}
	for _, r := range api.RoutesOrgUnitUser {
		key := &route.Key{
			Url:    r.Url,
			Method: r.Method,
		}
		entry := &route.Route{
			Key:      key,
			Endpoint: ep,
			Resource: r.Resource,
			Scopes:   r.Scopes,
			Verb:     r.Verb,
		}
		if err := routeTbl.Locate(context.Background(), key, entry); err != nil {
			log.Panicf("failed to register route %d %s: %s", r.Method, r.Url, err)
		}
	}
	return srv
}
