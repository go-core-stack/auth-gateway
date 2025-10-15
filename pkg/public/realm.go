package public

import (
	"encoding/json"
	"log"
	"net"
	"net/http"
	"strings"

	"github.com/go-core-stack/auth-gateway/pkg/table"
	"github.com/go-core-stack/core/errors"
)

type RealmInfoServer struct {
	http.Handler
	tenantTbl *table.TenantTable
}

type hostInfo struct {
	Host      string
	Domain    string
	SubDomain string
	Port      string
	IP        net.IP
}

func (s *RealmInfoServer) GetHostInfo(req *http.Request) (*hostInfo, error) {
	log.Printf("Got Host: %v", req.Host)
	log.Printf("Got URL Host: %v", req.URL.Host)
	host := req.Host
	if host == "" {
		return nil, errors.Wrapf(errors.InvalidArgument, "Invalid empty host")
	}

	var port string
	var err error
	if strings.Contains(host, ":") {
		host, port, err = net.SplitHostPort(host)
		if err != nil {
			return nil, errors.Wrapf(errors.InvalidArgument, "Invalid host: %v", err)
		}
	}

	info := &hostInfo{
		Host: host,
		Port: port,
	}

	if ip := net.ParseIP(host); ip != nil {
		info.IP = ip
	} else {
		subDomain, domain, _ := strings.Cut(host, ".")
		info.SubDomain = subDomain
		info.Domain = domain
	}

	return info, nil
}

type RealmConfig struct {
	Endpoint string `json:"endpoint,omitempty"`
	Realm    string `json:"realm,omitempty"`
	ClientId string `json:"clientId,omitempty"`
}

func (s *RealmInfoServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	info, err := s.GetHostInfo(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	realm := "root"
	if info != nil && info.SubDomain != "" {
		key := &table.TenantKey{
			Name: info.SubDomain,
		}
		_, err := s.tenantTbl.Find(r.Context(), key)
		if err == nil {
			// use realm from subdomain only if corresponding
			// tenant exists
			realm = info.SubDomain
		} else {
			log.Printf("Unknown tenant check: %s", info.SubDomain)
		}
	}

	data := &RealmConfig{
		Endpoint: "/",
		Realm:    realm,
		ClientId: "controller",
	}

	jsonData, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	//w.Header().Set("Content-Disposition", "attachment; filename=\"realm.json\"")

	_, err = w.Write(jsonData)
	if err != nil {
		log.Printf("Unable to send realm.json: %v", err)
	}
}

func NewRealmInfoServer() *RealmInfoServer {
	tbl, err := table.GetTenantTable()
	if err != nil {
		log.Panicf("failed to get Tenant table: %s", err)
	}
	return &RealmInfoServer{
		tenantTbl: tbl,
	}
}
