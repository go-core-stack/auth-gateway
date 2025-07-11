// Copyright © 2025 Prabhjot Singh Sethi, All Rights reserved
// Author: Prabhjot Singh Sethi <prabhjot.sethi@gmail.com>

// Code generated by protoc-gen-go-grpc. DO NOT EDIT.
// versions:
// - protoc-gen-go-grpc v1.5.1
// - protoc             v3.21.12
// source: resdef.proto

package api

import (
	context "context"
	grpc "google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
)

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
// Requires gRPC-Go v1.64.0 or later.
const _ = grpc.SupportPackageIsVersion9

const (
	ResourceDefinition_GetResources_FullMethodName = "/api.ResourceDefinition/GetResources"
)

// ResourceDefinitionClient is the client API for ResourceDefinition service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
//
// Service provided to expose available resource and actions
type ResourceDefinitionClient interface {
	// Get Resource definitions along with available actions
	GetResources(ctx context.Context, in *ResourceGetReq, opts ...grpc.CallOption) (*ResourceGetResp, error)
}

type resourceDefinitionClient struct {
	cc grpc.ClientConnInterface
}

func NewResourceDefinitionClient(cc grpc.ClientConnInterface) ResourceDefinitionClient {
	return &resourceDefinitionClient{cc}
}

func (c *resourceDefinitionClient) GetResources(ctx context.Context, in *ResourceGetReq, opts ...grpc.CallOption) (*ResourceGetResp, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(ResourceGetResp)
	err := c.cc.Invoke(ctx, ResourceDefinition_GetResources_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// ResourceDefinitionServer is the server API for ResourceDefinition service.
// All implementations must embed UnimplementedResourceDefinitionServer
// for forward compatibility.
//
// Service provided to expose available resource and actions
type ResourceDefinitionServer interface {
	// Get Resource definitions along with available actions
	GetResources(context.Context, *ResourceGetReq) (*ResourceGetResp, error)
	mustEmbedUnimplementedResourceDefinitionServer()
}

// UnimplementedResourceDefinitionServer must be embedded to have
// forward compatible implementations.
//
// NOTE: this should be embedded by value instead of pointer to avoid a nil
// pointer dereference when methods are called.
type UnimplementedResourceDefinitionServer struct{}

func (UnimplementedResourceDefinitionServer) GetResources(context.Context, *ResourceGetReq) (*ResourceGetResp, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetResources not implemented")
}
func (UnimplementedResourceDefinitionServer) mustEmbedUnimplementedResourceDefinitionServer() {}
func (UnimplementedResourceDefinitionServer) testEmbeddedByValue()                            {}

// UnsafeResourceDefinitionServer may be embedded to opt out of forward compatibility for this service.
// Use of this interface is not recommended, as added methods to ResourceDefinitionServer will
// result in compilation errors.
type UnsafeResourceDefinitionServer interface {
	mustEmbedUnimplementedResourceDefinitionServer()
}

func RegisterResourceDefinitionServer(s grpc.ServiceRegistrar, srv ResourceDefinitionServer) {
	// If the following call pancis, it indicates UnimplementedResourceDefinitionServer was
	// embedded by pointer and is nil.  This will cause panics if an
	// unimplemented method is ever invoked, so we test this at initialization
	// time to prevent it from happening at runtime later due to I/O.
	if t, ok := srv.(interface{ testEmbeddedByValue() }); ok {
		t.testEmbeddedByValue()
	}
	s.RegisterService(&ResourceDefinition_ServiceDesc, srv)
}

func _ResourceDefinition_GetResources_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ResourceGetReq)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(ResourceDefinitionServer).GetResources(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: ResourceDefinition_GetResources_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(ResourceDefinitionServer).GetResources(ctx, req.(*ResourceGetReq))
	}
	return interceptor(ctx, in, info, handler)
}

// ResourceDefinition_ServiceDesc is the grpc.ServiceDesc for ResourceDefinition service.
// It's only intended for direct use with grpc.RegisterService,
// and not to be introspected or modified (even as a copy)
var ResourceDefinition_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "api.ResourceDefinition",
	HandlerType: (*ResourceDefinitionServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "GetResources",
			Handler:    _ResourceDefinition_GetResources_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "resdef.proto",
}
