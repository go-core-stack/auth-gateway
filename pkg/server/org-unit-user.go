// Copyright © 2025 Prabhjot Singh Sethi, All Rights reserved
// Author: Prabhjot Singh Sethi <prabhjot.sethi@gmail.com>

package server

import (
	"context"
	"log"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/go-core-stack/auth/route"

	"github.com/go-core-stack/auth-gateway/api"
	"github.com/go-core-stack/auth-gateway/pkg/model"
)

type OrgUnitUserServer struct {
	api.UnimplementedOrgUnitUserServer
}

func (s *OrgUnitUserServer) ListOrgUnitUsers(ctx context.Context, req *api.OrgUnitUsersListReq) (*api.OrgUnitUsersListResp, error) {
	log.Printf("received list request for org unit roles: %v", req)
	resp := &api.OrgUnitUsersListResp{
		Count: 2,
		Items: []*api.OrgUnitUserListEntry{
			{
				Username:  "admin",
				Firstname: "Kluisz",
				Lastname:  "Administrator",
				Role:      "admin",
			},
			{
				Username:  "sample1",
				Firstname: "Test",
				Lastname:  "User 1",
				Role:      "default",
			},

			{
				Username:  "sample2",
				Firstname: "Test",
				Lastname:  "User 2",
				Role:      "auditor",
			},
		},
	}
	return resp, nil
}

func (s *OrgUnitUserServer) AddOrgUnitUser(ctx context.Context, req *api.OrgUnitUserAddReq) (*api.OrgUnitUserAddResp, error) {
	log.Printf("got request to add org unit user: %v", req)
	return nil, status.Errorf(codes.Unimplemented, "Add Org Unit User is not inplemented yet")
}
func (s *OrgUnitUserServer) UpdateOrgUnitUser(ctx context.Context, req *api.OrgUnitUserUpdateReq) (*api.OrgUnitUserUpdateResp, error) {
	log.Printf("got request to update org unit user: %v", req)
	return nil, status.Errorf(codes.Unimplemented, "Update Org Unit User is not inplemented yet")
}
func (s *OrgUnitUserServer) DeleteOrgUnitUser(ctx context.Context, req *api.OrgUnitUserDeleteReq) (*api.OrgUnitUserDeleteResp, error) {
	log.Printf("got request to delete org unit user: %v", req)
	return nil, status.Errorf(codes.Unimplemented, "Delete Org Unit User is not inplemented yet")
}

func NewOrgUnitUserServer(ctx *model.GrpcServerContext, ep string) *OrgUnitUserServer {
	srv := &OrgUnitUserServer{}
	api.RegisterOrgUnitUserServer(ctx.Server, srv)
	err := api.RegisterOrgUnitUserHandler(context.Background(), ctx.Mux, ctx.Conn)
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
