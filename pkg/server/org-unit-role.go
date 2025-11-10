// Copyright © 2025 Prabhjot Singh Sethi, All Rights reserved
// Author: Prabhjot Singh Sethi <prabhjot.sethi@gmail.com>

package server

import (
	"context"
	"log"

	auth "github.com/go-core-stack/auth/context"
	"github.com/go-core-stack/auth/route"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/go-core-stack/auth-gateway/api"
	"github.com/go-core-stack/auth-gateway/pkg/model"
)

type OrgUnitRoleServer struct {
	api.UnimplementedOrgUnitRoleServer
}

// Return only built-in roles (hardcoded)
// TODO: Custom roles will be added in a separate PR
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

// CreateCustomRole creates a new custom role for the org unit
// TODO: Implementation coming in a separate PR
func (s *OrgUnitRoleServer) CreateCustomRole(ctx context.Context, req *api.CreateCustomRoleReq) (*api.CreateCustomRoleResp, error) {
	authInfo, _ := auth.GetAuthInfoFromContext(ctx)
	if authInfo == nil {
		return nil, status.Errorf(codes.Unauthenticated, "User not authenticated")
	}

	// Stub implementation
	return nil, status.Errorf(codes.Unimplemented, "Custom role creation not yet implemented")
}

// UpdateCustomRole updates an existing custom role
// TODO: Implementation coming in a separate PR
func (s *OrgUnitRoleServer) UpdateCustomRole(ctx context.Context, req *api.UpdateCustomRoleReq) (*api.UpdateCustomRoleResp, error) {
	authInfo, _ := auth.GetAuthInfoFromContext(ctx)
	if authInfo == nil {
		return nil, status.Errorf(codes.Unauthenticated, "User not authenticated")
	}

	// Stub implementation
	return nil, status.Errorf(codes.Unimplemented, "Custom role update not yet implemented")
}

// GetCustomRole retrieves details of a specific custom role
// TODO: Implementation coming in a separate PR
func (s *OrgUnitRoleServer) GetCustomRole(ctx context.Context, req *api.GetCustomRoleReq) (*api.GetCustomRoleResp, error) {
	authInfo, _ := auth.GetAuthInfoFromContext(ctx)
	if authInfo == nil {
		return nil, status.Errorf(codes.Unauthenticated, "User not authenticated")
	}

	// Stub implementation
	return nil, status.Errorf(codes.Unimplemented, "Custom role retrieval not yet implemented")
}

// DeleteCustomRole deletes a custom role from the organization unit
// TODO: Implementation coming in a separate PR
func (s *OrgUnitRoleServer) DeleteCustomRole(ctx context.Context, req *api.DeleteCustomRoleReq) (*api.DeleteCustomRoleResp, error) {
	authInfo, _ := auth.GetAuthInfoFromContext(ctx)
	if authInfo == nil {
		return nil, status.Errorf(codes.Unauthenticated, "User not authenticated")
	}

	// TODO: Implement DeleteRoleWithBindingCheck logic here with proper atomicity:
	// Get table instances: table.GetOrgUnitRoleTable() and table.GetOrgUnitUserTable()
	// Check if role has bindings using HasRoleBindings() from OrgUnitUserTable
	// If has bindings:
	// -> Mark as deleted: Update() with isDeleted=true
	// -> Set updatedBy to authInfo.UserName
	// -> Role preserved in DB for audit/history
	// If no bindings:
	// -> Remove from database using DeleteKey()
	// Use database transaction or locks to ensure atomicity between check and delete

	// Stub implementation
	return nil, status.Errorf(codes.Unimplemented, "Custom role deletion not yet implemented")
}

// TODO: Implement CleanupOrphanedRoles as a background job or admin endpoint:
//   Query all roles with isDeleted=true for given tenant/orgUnit using FindMany()
//   For each deleted role, check if it still has bindings
//   If no bindings, remove from database using DeleteKey()
//   This reclaims space for roles that were marked deleted but users have since been removed

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
