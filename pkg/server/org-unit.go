// Copyright © 2025-2026 Prabhjot Singh Sethi, All Rights reserved
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

	"github.com/go-core-stack/auth-gateway/api"
	"github.com/go-core-stack/auth-gateway/pkg/config"
	"github.com/go-core-stack/auth-gateway/pkg/model"
	"github.com/go-core-stack/auth-gateway/pkg/table"
)

type OrgUnitServer struct {
	api.UnimplementedOrgUnitServer
	ouTable      *table.OrgUnitTable
	experimental config.ExperimentalConfig
}

// ouStatus derives the proto OrgUnitStatus from the entry's Deleted field.
func ouStatus(entry *table.OrgUnitEntry) api.OrgUnitStatus {
	if entry.Deleted > 0 {
		return api.OrgUnitStatus_Deleted
	}
	return api.OrgUnitStatus_Active
}

func (s *OrgUnitServer) ListOrgUnits(ctx context.Context, req *api.OrgUnitsListReq) (*api.OrgUnitsListResp, error) {
	authInfo, _ := auth.GetAuthInfoFromContext(ctx)
	if authInfo == nil {
		return nil, status.Errorf(codes.Unauthenticated, "User not authenticated")
	}
	OrgUnits, err := s.ouTable.FindByTenant(ctx, authInfo.Realm, "")
	if err != nil && !errors.IsNotFound(err) {
		log.Printf("got error while fetching org unit list for tenant %s: %s", authInfo.Realm, err)
		return nil, status.Errorf(codes.Internal, "Something went wrong, Please try again later")
	}

	resp := &api.OrgUnitsListResp{
		Count: int32(len(OrgUnits)),
	}

	for _, ou := range OrgUnits {
		item := &api.OrgUnitsListEntry{
			Id:        ou.Key.ID,
			Name:      ou.Name,
			Desc:      ou.Desc,
			Created:   ou.Created,
			CreatedBy: ou.CreatedBy,
			Status:    ouStatus(ou),
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
	update := &table.OrgUnitEntry{
		Key: &table.OrgUnitKey{
			ID: req.Id,
		},
		Name: req.Name,
		Desc: req.Desc,
	}
	found, err := s.ouTable.Find(ctx, update.Key)
	if err != nil {
		if errors.IsNotFound(err) {
			return nil, status.Errorf(codes.NotFound, "Org Unit with ID %s not found for tenant %s", req.Id, authInfo.Realm)
		}
		log.Printf("failed to find org unit for tenant %s: %s", authInfo.Realm, err)
		return nil, status.Errorf(codes.Internal, "Something went wrong, Please try again later")
	}
	if found.Tenant != authInfo.Realm {
		log.Printf("user belongs to %s, but trying to update org unit for %s", authInfo.Realm, found.Tenant)
		return nil, status.Errorf(codes.PermissionDenied, "You do not have permission to update this Org Unit")
	}
	// Guard: reject updates on soft-deleted OUs
	if found.Deleted > 0 {
		return nil, status.Errorf(codes.FailedPrecondition, "Org Unit %s has been deleted and cannot be updated", req.Id)
	}
	err = s.ouTable.Update(ctx, update.Key, update)
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
		Status:    ouStatus(entry),
		Deleted:   entry.Deleted,
	}, nil
}

func (s *OrgUnitServer) DeleteOrgUnit(ctx context.Context, req *api.OrgUnitDeleteReq) (*api.OrgUnitDeleteResp, error) {
	authInfo, _ := auth.GetAuthInfoFromContext(ctx)
	if authInfo == nil {
		return nil, status.Errorf(codes.Unauthenticated, "User not authenticated")
	}

	// Feature gate: soft-delete must be explicitly enabled
	if !s.experimental.AllowOUDelete {
		log.Printf("Got Delete Org unit request for ID: %s, but feature is disabled", req.Id)
		return nil, status.Errorf(codes.Unimplemented, "DeleteOrgUnit is not implemented yet")
	}

	key := &table.OrgUnitKey{
		ID: req.Id,
	}

	// Look up the OU to validate ownership
	found, err := s.ouTable.Find(ctx, key)
	if err != nil {
		if errors.IsNotFound(err) {
			return nil, status.Errorf(codes.NotFound, "Org Unit with ID %s not found", req.Id)
		}
		log.Printf("failed to find org unit %s for deletion: %s", req.Id, err)
		return nil, status.Errorf(codes.Internal, "Something went wrong, Please try again later")
	}

	if found.Tenant != authInfo.Realm {
		return nil, status.Errorf(codes.NotFound, "Org Unit with ID %s not found", req.Id)
	}

	// Idempotent: if already deleted, return success without changing
	// the timestamp
	if found.Deleted > 0 {
		return &api.OrgUnitDeleteResp{}, nil
	}

	// Set the deleted timestamp via update
	update := &table.OrgUnitEntry{
		Key:     key,
		Deleted: time.Now().Unix(),
	}

	err = s.ouTable.Update(ctx, key, update)
	if err != nil {
		log.Printf("failed to soft-delete org unit %s: %s", req.Id, err)
		return nil, status.Errorf(codes.Internal, "Something went wrong, Please try again later")
	}

	log.Printf("Soft-deleted org unit %s for tenant %s", req.Id, authInfo.Realm)
	return &api.OrgUnitDeleteResp{}, nil
}

func (s *OrgUnitServer) GetOrgUnitAccessLogs(ctx context.Context, req *api.OrgUnitAccessLogsGetReq) (*api.OrgUnitAccessLogsGetResp, error) {
	authInfo, _ := auth.GetAuthInfoFromContext(ctx)
	if authInfo == nil {
		return nil, status.Errorf(codes.Unauthenticated, "User not authenticated")
	}

	if req.Start == 0 || req.Start >= req.End {
		return nil, status.Errorf(codes.InvalidArgument, "Invalid time range specified")
	}

	resp := &api.OrgUnitAccessLogsGetResp{
		Items: []*api.OrgUnitAccessLog{
			{
				Timestamp: int64(1761550423),
				Ou:        "ou-123",
				User:      "admin",
				IpAddr:    "111.93.189.6",
				Method:    "GET",
				Status:    "200",
				Path:      "/api/v1",
				UserAgent: "Mozilla/5.0",
				Tenant:    "tenant-123",
			},
			{
				Timestamp: int64(1761540423),
				Ou:        "ou-123",
				User:      "admin",
				IpAddr:    "111.93.189.6",
				Method:    "PUT",
				Status:    "200",
				Path:      "/api/v1",
				UserAgent: "Mozilla/5.0",
				Tenant:    "tenant-123",
			},
		},
	}

	return resp, nil
}

func NewOrgUnitServer(ctx *model.GrpcServerContext, experimental config.ExperimentalConfig, ep string) *OrgUnitServer {
	ouTbl, err := table.GetOrgUnitTable()
	if err != nil {
		log.Panicf("failed to get Org Unit table: %s", err)
	}
	srv := &OrgUnitServer{
		ouTable:      ouTbl,
		experimental: experimental,
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
