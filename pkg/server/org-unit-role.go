// Copyright © 2025 Prabhjot Singh Sethi, All Rights reserved
// Author: Prabhjot Singh Sethi <prabhjot.sethi@gmail.com>

package server

import (
	"context"
	"fmt"
	"log"
	"time"

	auth "github.com/go-core-stack/auth/context"
	"github.com/go-core-stack/auth/route"
	"github.com/go-core-stack/core/errors"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/go-core-stack/auth-gateway/api"
	"github.com/go-core-stack/auth-gateway/pkg/model"
	"github.com/go-core-stack/auth-gateway/pkg/table"
)

type OrgUnitRoleServer struct {
	api.UnimplementedOrgUnitRoleServer
	customRoleTable *table.OrgUnitCustomRoleTable
}

// ListOrgUnitRoles returns both built-in and custom roles for an organization unit
func (s *OrgUnitRoleServer) ListOrgUnitRoles(ctx context.Context, req *api.OrgUnitRolesListReq) (*api.OrgUnitRolesListResp, error) {
	log.Printf("received list request for org unit roles: %v", req)

	authInfo, _ := auth.GetAuthInfoFromContext(ctx)
	if authInfo == nil {
		return nil, status.Errorf(codes.Unauthenticated, "User not authenticated")
	}

	items := []*api.OrgUnitRolesListEntry{
		{
			Name:        "admin",
			Desc:        "Administrator role to provide access to everything in the Organization Unit including management of users and resources",
			Type:        "built-in",
			DisplayName: "Administrator",
			Created:     0,
			CreatedBy:   "",
		},
		{
			Name:        "auditor",
			Desc:        "Auditor role to provide read-only access to all the resources available in the Organization Unit",
			Type:        "built-in",
			DisplayName: "Auditor",
			Created:     0,
			CreatedBy:   "",
		},
	}

	// Fetch custom roles from database
	customRoles, err := s.customRoleTable.GetByOrgUnit(ctx, authInfo.Realm, req.Ou, 0, 1000)
	if err != nil {
		log.Printf("failed to fetch custom roles: %s", err)
	} else {
		for _, role := range customRoles {
			items = append(items, &api.OrgUnitRolesListEntry{
				Name:        role.Key.Name,
				Desc:        role.Description,
				Type:        "custom",
				DisplayName: role.DisplayName,
				Created:     role.Created,
				CreatedBy:   role.CreatedBy,
			})
		}
	}

	resp := &api.OrgUnitRolesListResp{
		Items: items,
	}
	return resp, nil
}

// CreateCustomRole creates a new custom role for the org unit
func (s *OrgUnitRoleServer) CreateCustomRole(ctx context.Context, req *api.CreateCustomRoleReq) (*api.CreateCustomRoleResp, error) {
	authInfo, _ := auth.GetAuthInfoFromContext(ctx)
	if authInfo == nil {
		return nil, status.Errorf(codes.Unauthenticated, "User not authenticated")
	}

	if err := s.validateCreateCustomRoleRequest(req); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "Invalid request: %s", err)
	}

	// Validate that role name is not one of the system reserved names
	if req.Name == "admin" || req.Name == "default" || req.Name == "auditor" {
		return nil, status.Errorf(codes.InvalidArgument, "Role name '%s' is reserved and cannot be used for custom roles", req.Name)
	}

	// Check if there's an existing role (including soft-deleted ones) with the same name
	existingRole, err := s.customRoleTable.FindAnyByNameAndOrgUnit(ctx, authInfo.Realm, req.Ou, req.Name)
	if err == nil {
		// Role exists - check if it's active or soft-deleted with bindings
		if existingRole.Active == nil || *existingRole.Active {
			return nil, status.Errorf(codes.AlreadyExists, "Custom role '%s' already exists in organization unit", req.Name)
		}

		// Soft-deleted role exists - check if it has bindings
		hasBindings, err := s.customRoleTable.HasBindings(ctx, authInfo.Realm, req.Ou, req.Name)
		if err != nil {
			log.Printf("failed to check bindings for role %s: %s", req.Name, err)
			return nil, status.Errorf(codes.Internal, "Something went wrong, please try again later")
		}

		if hasBindings {
			return nil, status.Errorf(codes.AlreadyExists, "Custom role '%s' already exists in organization unit", req.Name)
		}

		// Soft-deleted role without bindings - can be permanently removed and recreated
		key := &table.OrgUnitCustomRoleKey{
			Tenant:    authInfo.Realm,
			OrgUnitId: req.Ou,
			Name:      req.Name,
		}
		err = s.customRoleTable.PermanentDelete(ctx, key)
		if err != nil {
			log.Printf("failed to permanently delete orphaned role %s: %s", req.Name, err)
			return nil, status.Errorf(codes.Internal, "Something went wrong, please try again later")
		}
	} else if !errors.IsNotFound(err) {
		log.Printf("failed to check existing role %s: %s", req.Name, err)
		return nil, status.Errorf(codes.Internal, "Something went wrong, please try again later")
	}

	// Convert protobuf permissions to table permissions
	permissions := s.convertProtoPermissionsToTable(req.Permissions)

	// Create the custom role entry
	customRole := &table.OrgUnitCustomRole{
		Key: &table.OrgUnitCustomRoleKey{
			Tenant:    authInfo.Realm,
			OrgUnitId: req.Ou,
			Name:      req.Name,
		},
		DisplayName: req.DisplayName,
		Description: req.Description,
		Permissions: permissions,
		Created:     time.Now().Unix(),
		CreatedBy:   authInfo.UserName,
		Active:      &[]bool{true}[0],
	}

	// Insert the custom role into the database
	err = s.customRoleTable.Insert(ctx, customRole.Key, customRole)
	if err != nil {
		if errors.IsAlreadyExists(err) {
			return nil, status.Errorf(codes.AlreadyExists, "Custom role '%s' already exists in organization unit", req.Name)
		}
		log.Printf("failed to create custom role: %s", err)
		return nil, status.Errorf(codes.Internal, "Something went wrong, please try again later")
	}

	return &api.CreateCustomRoleResp{
		Message: "Custom role created successfully",
	}, nil
}

// UpdateCustomRole updates an existing custom role
func (s *OrgUnitRoleServer) UpdateCustomRole(ctx context.Context, req *api.UpdateCustomRoleReq) (*api.UpdateCustomRoleResp, error) {
	authInfo, _ := auth.GetAuthInfoFromContext(ctx)
	if authInfo == nil {
		return nil, status.Errorf(codes.Unauthenticated, "User not authenticated")
	}

	if err := s.validateUpdateCustomRoleRequest(req); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "Invalid request: %s", err)
	}

	permissions := s.convertProtoPermissionsToTable(req.Permissions)

	updateRole := &table.OrgUnitCustomRole{
		DisplayName: req.DisplayName,
		Description: req.Description,
		Permissions: permissions,
		Updated:     time.Now().Unix(),
		UpdatedBy:   authInfo.UserName,
	}

	key := &table.OrgUnitCustomRoleKey{
		Tenant:    authInfo.Realm,
		OrgUnitId: req.Ou,
		Name:      req.Name,
	}

	err := s.customRoleTable.Update(ctx, key, updateRole)
	if err != nil {
		if errors.IsNotFound(err) {
			return nil, status.Errorf(codes.NotFound, "Custom role '%s' not found in organization unit", req.Name)
		}
		log.Printf("failed to update custom role: %s", err)
		return nil, status.Errorf(codes.Internal, "Something went wrong, please try again later")
	}

	return &api.UpdateCustomRoleResp{
		Message: "Custom role updated successfully",
	}, nil
}

// GetCustomRole retrieves details of a specific custom role
func (s *OrgUnitRoleServer) GetCustomRole(ctx context.Context, req *api.GetCustomRoleReq) (*api.GetCustomRoleResp, error) {
	authInfo, _ := auth.GetAuthInfoFromContext(ctx)
	if authInfo == nil {
		return nil, status.Errorf(codes.Unauthenticated, "User not authenticated")
	}

	customRole, err := s.customRoleTable.FindByNameAndOrgUnit(ctx, authInfo.Realm, req.Ou, req.Name)
	if err != nil {
		if errors.IsNotFound(err) {
			return nil, status.Errorf(codes.NotFound, "Custom role '%s' not found in organization unit", req.Name)
		}
		log.Printf("failed to get custom role: %s", err)
		return nil, status.Errorf(codes.Internal, "Something went wrong, please try again later")
	}

	permissions := s.convertTablePermissionsToProto(customRole.Permissions)

	return &api.GetCustomRoleResp{
		Name:        customRole.Key.Name,
		DisplayName: customRole.DisplayName,
		Description: customRole.Description,
		Permissions: permissions,
		Created:     customRole.Created,
		CreatedBy:   customRole.CreatedBy,
		Updated:     customRole.Updated,
		UpdatedBy:   customRole.UpdatedBy,
	}, nil
}

// DeleteCustomRole deletes a custom role from the organization unit
func (s *OrgUnitRoleServer) DeleteCustomRole(ctx context.Context, req *api.DeleteCustomRoleReq) (*api.DeleteCustomRoleResp, error) {
	authInfo, _ := auth.GetAuthInfoFromContext(ctx)
	if authInfo == nil {
		return nil, status.Errorf(codes.Unauthenticated, "User not authenticated")
	}

	key := &table.OrgUnitCustomRoleKey{
		Tenant:    authInfo.Realm,
		OrgUnitId: req.Ou,
		Name:      req.Name,
	}

	err := s.customRoleTable.DeleteCustomRoleWithBindingCheck(ctx, key, authInfo.UserName)
	if err != nil {
		if errors.IsNotFound(err) {
			return nil, status.Errorf(codes.NotFound, "Custom role '%s' not found in organization unit", req.Name)
		}
		log.Printf("failed to delete custom role: %s", err)
		return nil, status.Errorf(codes.Internal, "Something went wrong, please try again later")
	}

	return &api.DeleteCustomRoleResp{
		Message: "Custom role deleted successfully",
	}, nil
}

// convertProtoResourceMatchCriteriaToTable converts protobuf enum to table string constant
func (s *OrgUnitRoleServer) convertProtoResourceMatchCriteriaToTable(criteria api.ResourceMatchCriteria) table.ResourceMatchCriteria {
	switch criteria {
	case api.ResourceMatchCriteria_RESOURCE_MATCH_CRITERIA_EXACT:
		return table.ResourceMatchCriteriaExact
	case api.ResourceMatchCriteria_RESOURCE_MATCH_CRITERIA_PREFIX:
		return table.ResourceMatchCriteriaPrefix
	case api.ResourceMatchCriteria_RESOURCE_MATCH_CRITERIA_SUFFIX:
		return table.ResourceMatchCriteriaSuffix
	case api.ResourceMatchCriteria_RESOURCE_MATCH_CRITERIA_REGEX:
		return table.ResourceMatchCriteriaRegex
	case api.ResourceMatchCriteria_RESOURCE_MATCH_CRITERIA_WILDCARD:
		return table.ResourceMatchCriteriaWildcard
	case api.ResourceMatchCriteria_RESOURCE_MATCH_CRITERIA_UNSPECIFIED:
		fallthrough
	default:
		return table.ResourceMatchCriteriaUnspecified
	}
}

// convertTableResourceMatchCriteriaToProto converts table string constant to protobuf enum
func (s *OrgUnitRoleServer) convertTableResourceMatchCriteriaToProto(criteria table.ResourceMatchCriteria) api.ResourceMatchCriteria {
	switch criteria {
	case table.ResourceMatchCriteriaExact:
		return api.ResourceMatchCriteria_RESOURCE_MATCH_CRITERIA_EXACT
	case table.ResourceMatchCriteriaPrefix:
		return api.ResourceMatchCriteria_RESOURCE_MATCH_CRITERIA_PREFIX
	case table.ResourceMatchCriteriaSuffix:
		return api.ResourceMatchCriteria_RESOURCE_MATCH_CRITERIA_SUFFIX
	case table.ResourceMatchCriteriaRegex:
		return api.ResourceMatchCriteria_RESOURCE_MATCH_CRITERIA_REGEX
	case table.ResourceMatchCriteriaWildcard:
		return api.ResourceMatchCriteria_RESOURCE_MATCH_CRITERIA_WILDCARD
	case table.ResourceMatchCriteriaUnspecified:
		fallthrough
	default:
		return api.ResourceMatchCriteria_RESOURCE_MATCH_CRITERIA_UNSPECIFIED
	}
}

// convertProtoActionToTable converts protobuf enum to table string constant
func (s *OrgUnitRoleServer) convertProtoActionToTable(action api.RolePermissionAction) table.RolePermissionAction {
	switch action {
	case api.RolePermissionAction_ROLE_PERMISSION_ACTION_ALLOW:
		return table.RolePermissionActionAllow
	case api.RolePermissionAction_ROLE_PERMISSION_ACTION_DENY:
		return table.RolePermissionActionDeny
	case api.RolePermissionAction_ROLE_PERMISSION_ACTION_UNSPECIFIED:
		fallthrough
	default:
		return table.RolePermissionActionUnspecified
	}
}

// convertTableActionToProto converts table string constant to protobuf enum
func (s *OrgUnitRoleServer) convertTableActionToProto(action table.RolePermissionAction) api.RolePermissionAction {
	switch action {
	case table.RolePermissionActionAllow:
		return api.RolePermissionAction_ROLE_PERMISSION_ACTION_ALLOW
	case table.RolePermissionActionDeny:
		return api.RolePermissionAction_ROLE_PERMISSION_ACTION_DENY
	case table.RolePermissionActionUnspecified:
		fallthrough
	default:
		return api.RolePermissionAction_ROLE_PERMISSION_ACTION_UNSPECIFIED
	}
}

// convertProtoPermissionsToTable converts protobuf RolePermission slice to table RolePermission slice
func (s *OrgUnitRoleServer) convertProtoPermissionsToTable(protoPerms []*api.RolePermission) []*table.RolePermission {
	var permissions []*table.RolePermission
	for _, perm := range protoPerms {
		var match *table.ResourceMatch
		if perm.Match != nil {
			match = &table.ResourceMatch{
				Criteria: s.convertProtoResourceMatchCriteriaToTable(perm.Match.Criteria),
				Key:      perm.Match.Key,
			}
		}

		permissions = append(permissions, &table.RolePermission{
			Resource: perm.Resource,
			Match:    match,
			Verbs:    perm.Verbs,
			Action:   s.convertProtoActionToTable(perm.Action),
		})
	}
	return permissions
}

// convertTablePermissionsToProto converts table RolePermission slice to protobuf RolePermission slice
func (s *OrgUnitRoleServer) convertTablePermissionsToProto(tablePerms []*table.RolePermission) []*api.RolePermission {
	var permissions []*api.RolePermission
	for _, perm := range tablePerms {
		var match *api.ResourceMatch
		if perm.Match != nil {
			match = &api.ResourceMatch{
				Criteria: s.convertTableResourceMatchCriteriaToProto(perm.Match.Criteria),
				Key:      perm.Match.Key,
			}
		}

		permissions = append(permissions, &api.RolePermission{
			Resource: perm.Resource,
			Match:    match,
			Verbs:    perm.Verbs,
			Action:   s.convertTableActionToProto(perm.Action),
		})
	}
	return permissions
}

// validateCreateCustomRoleRequest validates the CreateCustomRole request fields
func (s *OrgUnitRoleServer) validateCreateCustomRoleRequest(req *api.CreateCustomRoleReq) error {
	if req.Name == "" {
		return errors.New("role name cannot be empty")
	}
	if len(req.Name) < 2 {
		return errors.New("role name must be at least 2 characters long")
	}
	if len(req.Name) > 50 {
		return errors.New("role name cannot exceed 50 characters")
	}

	if req.DisplayName == "" {
		return errors.New("display name cannot be empty")
	}
	if len(req.DisplayName) > 100 {
		return errors.New("display name cannot exceed 100 characters")
	}

	// Description is optional, but if provided, validate length
	if len(req.Description) > 500 {
		return errors.New("description cannot exceed 500 characters")
	}

	if len(req.Permissions) == 0 {
		return errors.New("at least one permission must be specified")
	}
	if len(req.Permissions) > 20 {
		return errors.New("cannot have more than 20 permissions per role")
	}

	for i, perm := range req.Permissions {
		if perm.Resource == "" {
			return fmt.Errorf("permission %d: resource cannot be empty", i+1)
		}
		if len(perm.Verbs) == 0 {
			return fmt.Errorf("permission %d: at least one verb must be specified", i+1)
		}
		for j, verb := range perm.Verbs {
			if verb == "" {
				return fmt.Errorf("permission %d, verb %d: verb cannot be empty", i+1, j+1)
			}
		}
		if perm.Action != api.RolePermissionAction_ROLE_PERMISSION_ACTION_UNSPECIFIED &&
			perm.Action != api.RolePermissionAction_ROLE_PERMISSION_ACTION_ALLOW &&
			perm.Action != api.RolePermissionAction_ROLE_PERMISSION_ACTION_DENY {
			return fmt.Errorf("permission %d: invalid action value: %v", i+1, perm.Action)
		}
	}

	return nil
}

// validateUpdateCustomRoleRequest validates the UpdateCustomRole request fields
func (s *OrgUnitRoleServer) validateUpdateCustomRoleRequest(req *api.UpdateCustomRoleReq) error {
	if req.DisplayName == "" {
		return errors.New("display name cannot be empty")
	}
	if len(req.DisplayName) > 100 {
		return errors.New("display name cannot exceed 100 characters")
	}

	// Description is optional, but if provided, validate length
	if len(req.Description) > 500 {
		return errors.New("description cannot exceed 500 characters")
	}

	if len(req.Permissions) == 0 {
		return errors.New("at least one permission must be specified")
	}
	if len(req.Permissions) > 20 {
		return errors.New("cannot have more than 20 permissions per role")
	}

	for i, perm := range req.Permissions {
		if perm.Resource == "" {
			return fmt.Errorf("permission %d: resource cannot be empty", i+1)
		}
		if len(perm.Verbs) == 0 {
			return fmt.Errorf("permission %d: at least one verb must be specified", i+1)
		}
		for j, verb := range perm.Verbs {
			if verb == "" {
				return fmt.Errorf("permission %d, verb %d: verb cannot be empty", i+1, j+1)
			}
		}
		if perm.Action != api.RolePermissionAction_ROLE_PERMISSION_ACTION_UNSPECIFIED &&
			perm.Action != api.RolePermissionAction_ROLE_PERMISSION_ACTION_ALLOW &&
			perm.Action != api.RolePermissionAction_ROLE_PERMISSION_ACTION_DENY {
			return fmt.Errorf("permission %d: invalid action value: %v", i+1, perm.Action)
		}
	}

	return nil
}

func NewOrgUnitRoleServer(ctx *model.GrpcServerContext, ep string) *OrgUnitRoleServer {
	customRoleTable, err := table.GetOrgUnitCustomRoleTable()
	if err != nil {
		log.Panicf("failed to get org unit custom role table: %s", err)
	}

	srv := &OrgUnitRoleServer{
		customRoleTable: customRoleTable,
	}
	api.RegisterOrgUnitRoleServer(ctx.Server, srv)
	err = api.RegisterOrgUnitRoleHandler(context.Background(), ctx.Mux, ctx.Conn)
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
