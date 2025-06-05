// Copyright © 2025 Prabhjot Singh Sethi, All Rights reserved
// Author: Prabhjot Singh Sethi <prabhjot.sethi@gmail.com>

package server

import (
	"context"
	"log"

	"github.com/Prabhjot-Sethi/auth-gateway/api"
	"github.com/Prabhjot-Sethi/auth-gateway/pkg/model"
	"github.com/go-core-stack/auth/route"
	"github.com/go-core-stack/core/utils"
)

type RegistrationServer struct {
	api.UnimplementedRegistrationServer
}

func (s *RegistrationServer) GetRegisterOtp(ctx context.Context, req *api.RegisterOtpReq) (*api.RegisterOtpResp, error) {
	log.Printf("got register OTP request: %v", req)
	return &api.RegisterOtpResp{}, nil
}

func NewRegistrationServer(ctx *model.GrpcServerContext, ep string) *RegistrationServer {
	srv := &RegistrationServer{}
	api.RegisterRegistrationServer(ctx.Server, srv)
	err := api.RegisterRegistrationHandler(context.Background(), ctx.Mux, ctx.Conn)
	if err != nil {
		log.Panicf("failed to register handler: %s", err)
	}
	routeTbl, err := route.GetRouteTable()
	if err != nil {
		log.Panicf("failed to get route table: %s", err)
	}
	for _, r := range api.RoutesRegistration {
		key := &route.Key{
			Url:    r.Url,
			Method: r.Method,
		}
		entry := &route.Route{
			Key:      key,
			Endpoint: ep,
			IsPublic: utils.BoolP(true),
		}
		if err := routeTbl.Locate(context.Background(), key, entry); err != nil {
			log.Panicf("failed to register route %d %s: %s", r.Method, r.Url, err)
		}
	}
	return srv
}
