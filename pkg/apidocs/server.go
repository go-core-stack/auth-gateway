// Copyright © 2025 Prabhjot Singh Sethi, All Rights reserved
// Author: Prabhjot Singh Sethi <prabhjot.sethi@gmail.com>

package apidocs

import (
	"io/fs"
	"log"
	"net/http"
	"net/http/httputil"
	"strings"

	"github.com/go-core-stack/auth-gateway/api"
)

func getLocalSwaggerHandler() http.Handler {
	//mime.AddExtensionType(".svg", "image/svg+xml")
	// Use subdirectory in embedded files
	subFS, err := fs.Sub(api.Swagger, "swagger")
	if err != nil {
		panic("couldn't create sub filesystem: " + err.Error())
	}
	return http.FileServer(http.FS(subFS))
}

type ApiDocsServer interface {
	ServeHTTP(http.ResponseWriter, *http.Request)
}

type apiDocsServer struct {
	http.Handler
	local   http.Handler
	proxyV1 *httputil.ReverseProxy
	proxyV2 *httputil.ReverseProxy
}

func (s *apiDocsServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// expected url to be of format /apidocs/<module/service>/..
	// TODO(prabhjot) eventually we may handle ports as part of this
	// and validate services providing apidocs
	tokens := strings.SplitN(r.URL.Path, "/", 4)

	if len(tokens) < 4 {
		r.URL.Path = "/" + tokens[2]
		// serve local swagger docs
		s.local.ServeHTTP(w, r)
		return
	}

	r.URL.Scheme = "http"
	// as of not always assume the service to be running on port 8080
	// TODO(prabhjot): eventually we need to handle configured ports
	r.URL.Host = tokens[2] + ":8080"
	// Set the Host header to match the URL host
	// This is important for the reverse proxy to work correctly
	// especially for HTTP/2 where the Host header is mandatory
	// and should match the authority of the request.
	// This is also important for HTTP/1.1 where the Host header
	// is used to determine the target host for the request.
	// This is required for the reverse proxy to work correctly
	// and to ensure that the backend server receives the correct
	// Host header.
	r.Host = r.URL.Host
	r.URL.Path = "/" + tokens[3]

	// support for HTTP/2 as well as HTTP/1.1
	if r.ProtoMajor == 2 {
		s.proxyV2.ServeHTTP(w, r)
	} else {
		s.proxyV1.ServeHTTP(w, r)
	}
}

func gatewayErrorHandler(w http.ResponseWriter, req *http.Request, err error) {
	log.Println("Api Docs proxy received error", err)
	http.Error(w, "Service temporarily unavailable, please try after sometime", http.StatusServiceUnavailable)
}

func NewApiDocsServer() ApiDocsServer {
	director := func(req *http.Request) {
		// we don't use director we will handle request modification
		// of our own
	}
	return &apiDocsServer{
		local: getLocalSwaggerHandler(),
		proxyV1: &httputil.ReverseProxy{
			Director:     director,
			ErrorHandler: gatewayErrorHandler,
		},
		proxyV2: &httputil.ReverseProxy{
			Director:     director,
			ErrorHandler: gatewayErrorHandler,
		},
	}
}
