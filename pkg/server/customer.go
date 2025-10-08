// Copyright © 2025 Prabhjot Singh Sethi, All Rights reserved
// Author: Prabhjot Singh Sethi <prabhjot.sethi@gmail.com>

package server

import (
	"context"
	"log"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/go-core-stack/auth/route"
	"github.com/go-core-stack/core/utils"

	"github.com/go-core-stack/auth-gateway/api"
	"github.com/go-core-stack/auth-gateway/pkg/model"
)

type CustomerServer struct {
	api.UnimplementedCustomerServer
}

func (s *CustomerServer) ListCustomers(ctx context.Context, req *api.CustomersListReq) (*api.CustomersListResp, error) {
	return &api.CustomersListResp{
		Count: 1,
		Items: []*api.CustomersListEntry{
			{
				Id:      "root",
				Name:    "Root",
				Desc:    "Root Customer created as part of deployment",
				Tenancy: api.CustomerDefs_Dedicated,
			},
		},
	}, nil
}

func (s *CustomerServer) AddCustomer(ctx context.Context, req *api.CustomerAddReq) (*api.CustomerAddResp, error) {
	log.Printf("Got Customer Add request for Name: %s, Desc: %s", req.Name, req.Desc)
	return nil, status.Errorf(codes.Unimplemented, "Add Customer is not implemented yet")
}

func (s *CustomerServer) UpdateCustomer(ctx context.Context, req *api.CustomerUpdateReq) (*api.CustomerUpdateResp, error) {
	log.Printf("Got Customer Update request for Name: %s, Desc: %s", req.Name, req.Desc)
	return nil, status.Errorf(codes.Unimplemented, "Update Customer is not implemented yet")
}

func (s *CustomerServer) GetCustomer(ctx context.Context, req *api.CustomerGetReq) (*api.CustomerGetResp, error) {
	return &api.CustomerGetResp{
		Id:        "root",
		Name:      "Root",
		Desc:      "Root Customer created as part of deployment",
		Created:   int64(1751907610),
		CreatedBy: "system",
		Tenancy:   api.CustomerDefs_Dedicated,
	}, nil
}

func (s *CustomerServer) DeleteCustomer(ctx context.Context, req *api.CustomerDeleteReq) (*api.CustomerDeleteResp, error) {
	log.Printf("Got Delete Customer request for ID: %s", req.Id)
	return nil, status.Errorf(codes.Unimplemented, "Delete Customer is not implemented yet")
}

func NewCustomerServer(ctx *model.GrpcServerContext, ep string) *CustomerServer {
	srv := &CustomerServer{}
	api.RegisterCustomerServer(ctx.Server, srv)
	err := api.RegisterCustomerHandler(context.Background(), ctx.Mux, ctx.Conn)
	if err != nil {
		log.Panicf("failed to register handler: %s", err)
	}
	tbl, err := route.GetRouteTable()
	if err != nil {
		log.Panicf("failed to get route table: %s", err)
	}
	for _, r := range api.RoutesCustomer {
		key := &route.Key{
			Url:    r.Url,
			Method: r.Method,
		}
		entry := &route.Route{
			Key:      key,
			Endpoint: ep,
			IsRoot:   utils.Pointer(true),
		}
		if err := tbl.Locate(context.Background(), key, entry); err != nil {
			log.Panicf("failed to register route %d %s: %s", r.Method, r.Url, err)
		}
	}
	return srv
}
