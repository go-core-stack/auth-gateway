// Copyright © 2025 Prabhjot Singh Sethi, All Rights reserved
// Author: Prabhjot Singh Sethi <prabhjot.sethi@gmail.com>

package server

import (
	"context"
	"log"

	"github.com/go-core-stack/auth-gateway/api"
	"github.com/go-core-stack/auth-gateway/pkg/keycloak"
	"github.com/go-core-stack/auth-gateway/pkg/model"
	"github.com/go-core-stack/auth/route"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type MyTenantServer struct {
	api.UnimplementedMyTenantServer
}

func (s *MyTenantServer) GetMyPasswordPolicy(context.Context, *api.MyPasswordPolicyGetReq) (*api.MyPasswordPolicyGetResp, error) {
	resp := &api.MyPasswordPolicyGetResp{
		MinLower:   1,
		MinUpper:   1,
		MinDigits:  1,
		MinSpecial: 1,
		MinLength:  4,
		MaxLength:  40,
	}
	return resp, nil
}

func (s *MyTenantServer) UpdateMyPasswordPolicy(context.Context, *api.MyPasswordPolicyUpdateReq) (*api.MyPasswordPolicyUpdateResp, error) {
	log.Printf("received request to update password policy")
	return nil, status.Errorf(codes.Unimplemented, "password policy update not implemented yet")
}

func NewMyTenantServer(ctx *model.GrpcServerContext, client *keycloak.Client, ep string) *MyTenantServer {
	srv := &MyTenantServer{}
	api.RegisterMyTenantServer(ctx.Server, srv)
	err := api.RegisterMyTenantHandler(context.Background(), ctx.Mux, ctx.Conn)
	if err != nil {
		log.Panicf("failed to register handler: %s", err)
	}
	tbl, err := route.GetRouteTable()
	if err != nil {
		log.Panicf("failed to get route table: %s", err)
	}
	for _, r := range api.RoutesMyTenant {
		key := &route.Key{
			Url:    r.Url,
			Method: r.Method,
		}
		entry := &route.Route{
			Key:      key,
			Endpoint: ep,
			Resource: r.Resource,
			Verb:     r.Verb,
		}
		if err := tbl.Locate(context.Background(), key, entry); err != nil {
			log.Panicf("failed to register route %d %s: %s", r.Method, r.Url, err)
		}
	}
	return srv
}
