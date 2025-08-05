// Copyright © 2025 Prabhjot Singh Sethi, All Rights reserved
// Author: Prabhjot Singh Sethi <prabhjot.sethi@gmail.com>

package server

import (
	"context"
	"log"

	"github.com/go-core-stack/auth/route"

	"github.com/go-core-stack/auth-gateway/api"
	"github.com/go-core-stack/auth-gateway/pkg/model"
)

type OrgUnitRoleServer struct {
	api.UnimplementedOrgUnitRoleServer
}

func (s *OrgUnitRoleServer) ListOrgUnitRoles(ctx context.Context, req *api.OrgUnitRolesListReq) (*api.OrgUnitRolesListResp, error) {
	log.Printf("received list request for org unit roles: %v", req)
	resp := &api.OrgUnitRolesListResp{
		Items: []*api.OrgUnitRolesListEntry{
			{
				Name: "default",
				Desc: "Standard user role to provide access to all the resources available in the Organization Unit",
			},
			{
				Name: "admin",
				Desc: "Administrator role to provide access to everything in the Organization Unit including management of users and resources",
			},
			{
				Name: "auditor",
				Desc: "Auditor role to provider read-only access to all the resources available in the Organization Unit",
			},
		},
	}
	return resp, nil
}

func NewOrgUnitRoleServer(ctx *model.GrpcServerContext, ep string) *OrgUnitRoleServer {
	srv := &OrgUnitRoleServer{}
	api.RegisterOrgUnitRoleServer(ctx.Server, srv)
	err := api.RegisterOrgUnitRoleHandler(context.Background(), ctx.Mux, ctx.Conn)
	if err != nil {
		log.Panicf("failed to register handler: %s", err)
	}
	routeTbl, err := route.GetRouteTable()
	if err != nil {
		log.Panicf("failed to get route table: %s", err)
	}
	for _, r := range api.RoutesOrgUnitRole {
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
