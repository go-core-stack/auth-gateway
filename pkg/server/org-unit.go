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
	"github.com/google/uuid"

	"github.com/Prabhjot-Sethi/auth-gateway/api"
	"github.com/Prabhjot-Sethi/auth-gateway/pkg/model"
	"github.com/Prabhjot-Sethi/auth-gateway/pkg/table"
)

type OrgUnitServer struct {
	api.UnimplementedOrgUnitServer
	ouTable *table.OrgUnitTable
}

func (s *OrgUnitServer) ListOrgUnits(ctx context.Context, req *api.OrgUnitsListReq) (*api.OrgUnitsListResp, error) {
	authInfo, _ := auth.GetAuthInfoFromContext(ctx)
	if authInfo == nil {
		return nil, status.Errorf(codes.Unauthenticated, "User not authenticated")
	}
	OrgUnits, err := s.ouTable.FindByTenant(ctx, authInfo.Realm)
	if err != nil {
		if errors.IsNotFound(err) {
			return nil, status.Errorf(codes.NotFound, "No Org Unit available for tenant %s", authInfo.Realm)
		}
		log.Printf("got error while fetching org unit list for tenant %s: %s", authInfo.Realm, err)
		return nil, status.Errorf(codes.Internal, "Something went wrong, Please try again later")
	}
	resp := &api.OrgUnitsListResp{}
	for _, ou := range OrgUnits {
		item := &api.OrgUnitsListEntry{
			Id:        ou.Key.ID,
			Name:      ou.Name,
			Desc:      ou.Desc,
			Created:   ou.Created,
			CreatedBy: ou.CreatedBy,
		}
		resp.Items = append(resp.Items, item)
	}

	return resp, nil
}

func (s *OrgUnitServer) CreateOrgUnit(ctx context.Context, req *api.OrgUnitCreateReq) (*api.OrgUnitCreateResp, error) {
	authInfo, _ := auth.GetAuthInfoFromContext(ctx)
	if authInfo == nil {
		return nil, status.Errorf(codes.Unauthenticated, "User not authenticated")
	}
	entry := &table.OrgUnitEntry{
		Key: &table.OrgUnitKey{
			ID: uuid.New().String(),
		},
		Name:      req.Name,
		Desc:      req.Desc,
		Tenant:    authInfo.Realm,
		Created:   time.Now().Unix(),
		CreatedBy: authInfo.UserName,
	}
	err := s.ouTable.Insert(ctx, entry.Key, entry)
	if err != nil {
		log.Printf("failed to create org unit for tenant %s: %s", authInfo.Realm, err)
		return nil, status.Errorf(codes.Internal, "Something went wrong, Please try again later")
	}
	return &api.OrgUnitCreateResp{
		Id: entry.Key.ID,
	}, nil
}

func (s *OrgUnitServer) UpdateOrgUnit(ctx context.Context, req *api.OrgUnitUpdateReq) (*api.OrgUnitUpdateResp, error) {
	authInfo, _ := auth.GetAuthInfoFromContext(ctx)
	if authInfo == nil {
		return nil, status.Errorf(codes.Unauthenticated, "User not authenticated")
	}
	entry := &table.OrgUnitEntry{
		Key: &table.OrgUnitKey{
			ID: req.Id,
		},
		Name: req.Name,
		Desc: req.Desc,
	}
	_, err := s.ouTable.Find(ctx, entry.Key)
	if err != nil {
		if errors.IsNotFound(err) {
			return nil, status.Errorf(codes.NotFound, "Org Unit with ID %s not found for tenant %s", req.Id, authInfo.Realm)
		}
		log.Printf("failed to find org unit for tenant %s: %s", authInfo.Realm, err)
		return nil, status.Errorf(codes.Internal, "Something went wrong, Please try again later")
	}
	if entry.Tenant != authInfo.Realm {
		return nil, status.Errorf(codes.PermissionDenied, "You do not have permission to update this Org Unit")
	}
	err = s.ouTable.Update(ctx, entry.Key, entry)
	if err != nil {
		log.Printf("failed to update org unit for tenant %s: %s", authInfo.Realm, err)
		return nil, status.Errorf(codes.Internal, "Something went wrong, Please try again later")
	}
	return &api.OrgUnitUpdateResp{}, nil
}

func (s *OrgUnitServer) GetOrgUnit(ctx context.Context, req *api.OrgUnitGetReq) (*api.OrgUnitGetResp, error) {
	authInfo, _ := auth.GetAuthInfoFromContext(ctx)
	if authInfo == nil {
		return nil, status.Errorf(codes.Unauthenticated, "User not authenticated")
	}
	key := &table.OrgUnitKey{
		ID: req.Id,
	}
	entry, err := s.ouTable.Find(ctx, key)
	if err != nil {
		if errors.IsNotFound(err) {
			return nil, status.Errorf(codes.NotFound, "Org Unit with ID %s not found", req.Id)
		}
		log.Printf("failed to find org unit for tenant %s: %s", authInfo.Realm, err)
		return nil, status.Errorf(codes.Internal, "Something went wrong, Please try again later")
	}
	if entry.Tenant != authInfo.Realm {
		return nil, status.Errorf(codes.NotFound, "Org Unit with ID %s not found", req.Id)
	}

	return &api.OrgUnitGetResp{
		Id:        entry.Key.ID,
		Name:      entry.Name,
		Desc:      entry.Desc,
		Created:   entry.Created,
		CreatedBy: entry.CreatedBy,
	}, nil
}

func (s *OrgUnitServer) DeleteOrgUnit(ctx context.Context, req *api.OrgUnitDeleteReq) (*api.OrgUnitDeleteResp, error) {
	log.Printf("Got Delete Org unit request for ID: %s", req.Id)
	return nil, status.Errorf(codes.Unimplemented, "DeleteOrgUnit is not implemented yet")
}

func NewOrgUnitServer(ctx *model.GrpcServerContext, ep string) *OrgUnitServer {
	ouTbl, err := table.GetOrgUnitTable()
	if err != nil {
		log.Panicf("failed to get Org Unit table: %s", err)
	}
	srv := &OrgUnitServer{
		ouTable: ouTbl, // Initialize the Org Unit table
	}
	api.RegisterOrgUnitServer(ctx.Server, srv)
	err = api.RegisterOrgUnitHandler(context.Background(), ctx.Mux, ctx.Conn)
	if err != nil {
		log.Panicf("failed to register handler: %s", err)
	}
	tbl, err := route.GetRouteTable()
	if err != nil {
		log.Panicf("failed to get route table: %s", err)
	}
	for _, r := range api.RoutesOrgUnit {
		key := &route.Key{
			Url:    r.Url,
			Method: r.Method,
		}
		entry := &route.Route{
			Key:      key,
			Endpoint: ep,
		}
		if err := tbl.Locate(context.Background(), key, entry); err != nil {
			log.Panicf("failed to register route %d %s: %s", r.Method, r.Url, err)
		}
	}
	return srv
}
