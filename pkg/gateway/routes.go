// Copyright © 2025-2026 Prabhjot Singh Sethi, All Rights reserved
// Author: Prabhjot Singh Sethi <prabhjot.sethi@gmail.com>

package gateway

import (
	"context"
	"log"
	"net/http"
	"net/url"
	"sync"

	"github.com/go-core-stack/auth/route"
	"github.com/go-core-stack/core/errors"
	"github.com/go-core-stack/core/utils"
	"github.com/go-core-stack/patricia"
)

// canonicalOrgUnitScope is the scope name (and path-param key) that
// auth-gateway uses internally to recognize an org-unit-scoped route.
// A deployment may configure an alias (e.g. "workspace") that the
// gateway will accept as semantically equivalent.
const canonicalOrgUnitScope = "ou"

type routeData struct {
	scheme         string
	host           string
	isPublic       bool
	isRoot         bool
	isUserSpecific bool
	scopes         []string
}

type routeNodes map[route.MethodType]routeData

var routeLock sync.RWMutex
var gwRoutes = patricia.NewUrlTree[*routeNodes]()

func populateRoutes(routes *route.RouteTable) {
	list, err := routes.FindMany(context.Background(), nil, 0, 0)
	if err != nil {
		log.Printf("Failed to find routes: %s", err)
		return
	}
	nRoutes := patricia.NewUrlTree[*routeNodes]()
	for _, r := range list {
		ep, _ := url.Parse(r.Endpoint)
		_, _, node, ok := nRoutes.Match(r.Key.Url)
		if !ok {
			node = &routeNodes{
				r.Key.Method: {
					scheme:         ep.Scheme,
					host:           ep.Host,
					isPublic:       utils.Dereference(r.IsPublic),
					isRoot:         utils.Dereference(r.IsRoot),
					isUserSpecific: utils.Dereference(r.IsUserSpecific),
					scopes:         r.Scopes,
				},
			}
			nRoutes.Insert(r.Key.Url, node)
		} else {
			(*node)[r.Key.Method] = routeData{
				scheme:         ep.Scheme,
				host:           ep.Host,
				isPublic:       utils.Dereference(r.IsPublic),
				isRoot:         utils.Dereference(r.IsRoot),
				isUserSpecific: utils.Dereference(r.IsUserSpecific),
				scopes:         r.Scopes,
			}
		}
	}
	// take a lock before updating the global routes
	routeLock.Lock()
	defer routeLock.Unlock()
	gwRoutes = nRoutes
}

// isOrgUnitScope reports whether the given scope/key name is recognized
// as an org-unit reference, accepting either the canonical "ou" or the
// optional configured alias (e.g. "workspace"). When alias is empty, only
// the canonical form is accepted.
func isOrgUnitScope(name, alias string) bool {
	if name == canonicalOrgUnitScope {
		return true
	}
	if alias != "" && name == alias {
		return true
	}
	return false
}

func matchRoute(m string, url string, orgUnitAlias string) (*routeData, string, error) {
	var node *routeNodes
	var ok bool
	var keys, values []string

	func() {
		routeLock.RLock()
		defer routeLock.RUnlock()

		keys, values, node, ok = gwRoutes.Match(url)
	}()

	if !ok {
		return nil, "", errors.Wrapf(errors.NotFound, "route not found for %s", url)
	}

	var method route.MethodType
	switch m {
	case http.MethodGet:
		method = route.GET
	case http.MethodPost:
		method = route.POST
	case http.MethodPut:
		method = route.PUT
	case http.MethodDelete:
		method = route.DELETE
	case http.MethodConnect:
		method = route.CONNECT
	case http.MethodPatch:
		method = route.PATCH
	case http.MethodHead:
		method = route.HEAD
	case http.MethodOptions:
		method = route.OPTIONS
	case http.MethodTrace:
		method = route.TRACE
	default:
		return nil, "", errors.Wrapf(errors.InvalidArgument, "invalid method %s", m)
	}

	data, ok := (*node)[method]
	if !ok {
		return nil, "", errors.Wrapf(errors.NotFound, "route not found for %s", url)
	}

	orgUnit := ""
	switch len(data.scopes) {
	case 1:
		// An alias-scoped route (e.g. scope "workspace") is treated
		// as equivalent to "ou" so the existing org-unit RBAC pipeline
		// applies unchanged.
		if !isOrgUnitScope(data.scopes[0], orgUnitAlias) {
			return nil, "", errors.Wrapf(errors.InvalidArgument, "invalid scope %s for %s", data.scopes[0], url)
		}
		for i, k := range keys {
			if isOrgUnitScope(k, orgUnitAlias) {
				orgUnit = values[i]
				break
			}
		}
		if orgUnit == "" {
			return nil, "", errors.Wrapf(errors.InvalidArgument, "org unit not found")
		}
	case 0:
		break
	default:
		return nil, "", errors.Wrapf(errors.InvalidArgument, "multiple scopes found for %s", url)
	}

	return &data, orgUnit, nil
}
