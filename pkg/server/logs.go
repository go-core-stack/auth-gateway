package server

import (
	"context"
	"log"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/go-core-stack/auth-gateway/pkg/model"
	auth "github.com/go-core-stack/auth/context"
	"github.com/go-core-stack/auth/route"

	"github.com/go-core-stack/auth-gateway/api"
)

type AccessLogsServer struct {
	api.UnimplementedAccessLogsServer
}

func (s *AccessLogsServer) GetAccessLogs(ctx context.Context, req *api.AccessLogsGetReq) (*api.AccessLogsGetResp, error) {
	authInfo, _ := auth.GetAuthInfoFromContext(ctx)
	if authInfo == nil {
		return nil, status.Errorf(codes.Unauthenticated, "User not authenticated")
	}

	// build filters based on ou and bucket name
	// bucket name is optional
	filters := make(map[string]string)
	if req.Ou != "" {
		filters["ou"] = req.Ou
	}

	if req.Start == 0 || req.End == 0 {
		return nil, status.Errorf(codes.InvalidArgument, "Invalid time range specified")
	}

	// Hardcoded AccessLogsGetResp for testing
	resp := &api.AccessLogsGetResp{
		Items: []*api.AccessLogItem{
			{
				Timestamp:      "2025-09-22T12:00:00Z",
				RequestAction:  "GET",
				Ou:             "ou-123",
				RequestTime:    "1758513600",
				Email:          "test.user@example.com",
				RemoteIp:       "192.168.1.100",
				Method:         "GET",
				Path:           "/api/v1",
				HttpStatusCode: "200",
				UserAgent:      "Mozilla/5.0",
				Level:          "INFO",
				Tenant:         "tenant-123",
			},
			{
				Timestamp:      "2025-09-22T12:05:00Z",
				RequestAction:  "PUT",
				Ou:             "ou-123",
				RequestTime:    "1758513600",
				Email:          "admin@example.com",
				RemoteIp:       "192.168.1.101",
				Method:         "PUT",
				Path:           "/api/v1",
				HttpStatusCode: "201",
				UserAgent:      "curl/8.0",
				Level:          "INFO",
				Tenant:         "tenant-456",
			},
		},
	}

	return resp, nil
}

func NewAccessLogsServer(ctx *model.GrpcServerContext, ep string) *AccessLogsServer {
	srv := &AccessLogsServer{}

	api.RegisterAccessLogsServer(ctx.Server, srv)

	err := api.RegisterAccessLogsHandler(context.Background(), ctx.Mux, ctx.Conn)
	if err != nil {
		log.Panicf("Failed to register AccessLogs handler: %s", err)
	}

	routeTbl, err := route.GetRouteTable()
	if err != nil {
		log.Panicf("failed to get route table: %s", err)
	}

	for _, r := range api.RoutesAccessLogs {
		key := &route.Key{
			Url:    r.Url,
			Method: r.Method,
		}
		entry := &route.Route{
			Key:      key,
			Endpoint: ep,
			Resource: r.Resource,
			Verb:     r.Verb,
			Scopes:   r.Scopes,
		}
		if err := routeTbl.Locate(context.Background(), key, entry); err != nil {
			log.Panicf("failed to register route %+v: %s", key, err)
		}
	}

	return srv
}
