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
	"github.com/go-core-stack/auth-gateway/pkg/table"
)

type CustomerServer struct {
	api.UnimplementedCustomerServer
	customerTbl *table.CustomerTable
}

func (s *CustomerServer) ListCustomers(ctx context.Context, req *api.CustomersListReq) (*api.CustomersListResp, error) {
	count, err := s.customerTbl.Count(ctx, nil)
	if err != nil {
		log.Printf("Error getting count of available customers: %s", err)
		return nil, status.Errorf(codes.Internal, "Something went wrong, please try again later")
	}
	resp := &api.CustomersListResp{
		Count: int32(count),
		Items: []*api.CustomersListEntry{},
	}

	list, err := s.customerTbl.FindMany(ctx, nil, req.Offset, req.Limit)
	if err != nil {
		log.Printf("Error getting list of available customers: %s", err)
		return nil, status.Errorf(codes.Internal, "Something went wrong, please try again later")
	}

	for _, cust := range list {
		item := &api.CustomersListEntry{
			Id:   cust.Key.Id,
			Name: cust.Config.Name,
			Desc: cust.Config.Desc,
		}
		switch cust.Tenancy {
		case table.DedicatedTenancy:
			item.Tenancy = api.CustomerDefs_Dedicated
		case table.SharedTenancy:
			item.Tenancy = api.CustomerDefs_Shared
		}
		resp.Items = append(resp.Items, item)
	}

	return resp, nil
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
	key := &table.CustomerKey{
		Id: req.Id,
	}
	entry, err := s.customerTbl.Find(ctx, key)
	if err != nil {
		log.Printf("Error getting customer %s: %s", req.Id, err)
		return nil, status.Errorf(codes.Internal, "Something went wrong, please try again later")
	}

	tenancy := api.CustomerDefs_Dedicated
	if entry.Tenancy == table.SharedTenancy {
		tenancy = api.CustomerDefs_Shared
	}

	return &api.CustomerGetResp{
		Id:        entry.Key.Id,
		Name:      entry.Config.Name,
		Desc:      entry.Config.Desc,
		Created:   entry.Created,
		CreatedBy: entry.CreatedBy,
		Tenancy:   tenancy,
	}, nil
}

func (s *CustomerServer) DeleteCustomer(ctx context.Context, req *api.CustomerDeleteReq) (*api.CustomerDeleteResp, error) {
	log.Printf("Got Delete Customer request for ID: %s", req.Id)
	return nil, status.Errorf(codes.Unimplemented, "Delete Customer is not implemented yet")
}

func NewCustomerServer(ctx *model.GrpcServerContext, ep string) *CustomerServer {
	customerTbl, err := table.GetCustomerTable()
	if err != nil {
		log.Panicf("failed to get customer table: %s", err)
	}
	srv := &CustomerServer{
		customerTbl: customerTbl,
	}
	api.RegisterCustomerServer(ctx.Server, srv)
	err = api.RegisterCustomerHandler(context.Background(), ctx.Mux, ctx.Conn)
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
