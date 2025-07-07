// Copyright © 2025 Prabhjot Singh Sethi, All Rights reserved
// Author: Prabhjot Singh Sethi <prabhjot.sethi@gmail.com>

package server

import (
	"context"
	"log"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	auth "github.com/go-core-stack/auth/context"
	"github.com/go-core-stack/auth/route"
	"github.com/go-core-stack/core/utils"

	"github.com/go-core-stack/auth-gateway/api"
	"github.com/go-core-stack/auth-gateway/pkg/controller/roledef"
	"github.com/go-core-stack/auth-gateway/pkg/model"
)

type ResourceDefinitionServer struct {
	api.UnimplementedResourceDefinitionServer
	mgr *roledef.ResourceManager
}

func (s *ResourceDefinitionServer) GetResources(ctx context.Context, req *api.ResourceGetReq) (*api.ResourceGetResp, error) {
	info, err := auth.GetAuthInfoFromContext(ctx)
	if err != nil {
		return nil, status.Errorf(codes.Unauthenticated, "Authentication required: %s", err.Error())
	}
	resp := &api.ResourceGetResp{}
	resources := s.mgr.GetResourcesDef(info.IsRoot)
	for k, v := range resources.All() {
		item := &api.ResourceEntry{
			Name:  k,
			Verbs: v,
		}
		resp.Items = append(resp.Items, item)
	}
	return resp, nil
}

func NewResourceDefinitionServer(ctx *model.GrpcServerContext, mgr *roledef.ResourceManager, ep string) *ResourceDefinitionServer {
	srv := &ResourceDefinitionServer{
		mgr: mgr,
	}
	api.RegisterResourceDefinitionServer(ctx.Server, srv)
	err := api.RegisterResourceDefinitionHandler(context.Background(), ctx.Mux, ctx.Conn)
	if err != nil {
		log.Panicf("failed to register handler: %s", err)
	}
	routeTbl, err := route.GetRouteTable()
	if err != nil {
		log.Panicf("failed to get route table: %s", err)
	}
	for _, r := range api.RoutesResourceDefinition {
		key := &route.Key{
			Url:    r.Url,
			Method: r.Method,
		}
		entry := &route.Route{
			Key:            key,
			Endpoint:       ep,
			IsUserSpecific: utils.BoolP(true), // these routes are available only if user is logged in, and are rendered based on tenancy
		}
		if err := routeTbl.Locate(context.Background(), key, entry); err != nil {
			log.Panicf("failed to register route %d %s: %s", r.Method, r.Url, err)
		}
	}
	return srv
}
