// Copyright © 2025 Prabhjot Singh Sethi, All Rights reserved
// Author: Prabhjot Singh Sethi <prabhjot.sethi@gmail.com>

package api

//go:generate protoc -I . -I ../third_party --go_out=. --go_opt=paths=source_relative --go-grpc_out=. --go-grpc_opt=paths=source_relative --grpc-gateway_out . --grpc-gateway_opt paths=source_relative  --routes_out . --routes_opt paths=source_relative --openapiv2_out ./swagger --openapiv2_opt logtostderr=true --openapiv2_opt allow_merge=true user.proto myaccount.proto
