// Copyright © 2025 Prabhjot Singh Sethi, All Rights reserved
// Author: Prabhjot Singh Sethi <prabhjot.sethi@gmail.com>

package roledef

import (
	"context"
	"log"
	"slices"
	"sync"
	"time"

	"github.com/go-core-stack/auth/route"
	"github.com/go-core-stack/core/reconciler"
	"github.com/go-core-stack/core/utils"
	"github.com/go-core-stack/patricia"
)

type resVerbs struct {
	Verbs []string
}

type resNode struct {
	Resources map[string]*resVerbs
}

type resourceReconciler struct {
	reconciler.Controller
	mu  sync.Mutex
	mgr *ResourceManager
}

func (r *resourceReconciler) compileResourceDef() {
	list, err := r.mgr.routes.FindMany(context.Background(), nil)
	if err != nil {
		log.Printf("Failed to find routes: %s", err)
		return
	}
	var current *resNode
	user := &resNode{
		Resources: map[string]*resVerbs{},
	}
	root := &resNode{
		Resources: map[string]*resVerbs{},
	}
	for _, rt := range list {
		if utils.PBool(rt.IsPublic) || utils.PBool(rt.IsUserSpecific) {
			continue
		}
		if utils.PBool(rt.IsRoot) {
			current = root
		} else {
			current = user
		}
		if rt.Resource != "" {
			v, ok := current.Resources[rt.Resource]
			if !ok {
				v = &resVerbs{}
				current.Resources[rt.Resource] = v
			}
			v.Verbs = append(v.Verbs, rt.Verb)
			slices.Sort(v.Verbs)
		}
	}
	for k, v := range root.Resources {
		log.Printf("For root resource :%s, got following actions", k)
		for _, verb := range v.Verbs {
			log.Printf("\tverb: %s", verb)
		}
	}
	r.mgr.root = root
	for k, v := range user.Resources {
		log.Printf("For user resource :%s, got following actions", k)
		for _, verb := range v.Verbs {
			log.Printf("\tverb: %s", verb)
		}
	}
	r.mgr.user = user
	log.Println("Printing role def for regular tenant")
	_ = r.mgr.GetResourcesDef(false)
	log.Println("Printing role def for root tenant")
	_ = r.mgr.GetResourcesDef(true)
}

func (r *resourceReconciler) Reconcile(k any) (*reconciler.Result, error) {
	ok := r.mu.TryLock()
	if !ok {
		return &reconciler.Result{}, nil
	}
	go func() {
		time.Sleep(3 * time.Second)
		log.Printf("handling reconciler trigger:%v", k)
		r.compileResourceDef()
		r.mu.Unlock()
	}()
	return &reconciler.Result{}, nil
}

type ResourceManager struct {
	r      *resourceReconciler
	routes *route.RouteTable
	root   *resNode
	user   *resNode
}

func (m *ResourceManager) GetResourcesDef(rootTenant bool) patricia.SimpleTree[[]string] {
	resp := patricia.NewSimpleTree[[]string]()
	for k, v := range m.user.Resources {
		_ = resp.Insert(k, v.Verbs)
	}
	if rootTenant {
		for k, v := range m.root.Resources {
			_ = resp.Insert(k, v.Verbs)
		}
	}
	for k, v := range resp.All() {
		log.Printf("\t\tgot Role: %s, Verbs: %v", k, v)
	}
	found, _ := resp.Search("user")
	log.Printf("\tfound Role: %s, Verbs: %v", "user", found)
	return resp
}

func NewResourceManager() *ResourceManager {
	routes, err := route.GetRouteTable()
	if err != nil {
		log.Panicf("unable to get route table: %s", err)
	}

	mgr := &ResourceManager{
		routes: routes,
	}

	mgr.r = &resourceReconciler{
		mgr: mgr,
	}

	err = routes.Register("ResourceDefinition", mgr.r)
	if err != nil {
		log.Panicf("Failed to register Resource Definition Manager: %s", err)
	}

	return mgr
}
