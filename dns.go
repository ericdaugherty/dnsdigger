package dnsdigger

import (
	"errors"
	"fmt"
	"net"
	"sort"
	"strings"

	"golang.org/x/net/context"
)

var owners = map[string]string{
	"amazonaws.com":     "Amazon.com, Inc.",
	"1e100.net":         "Google LLC",
	"domaincontrol.com": "GoDaddy",
	"cloudflare.com":    "CloudFlare",
}

const unknownOwner = "Unknown"

var commonTXTRecords = []string{"", "_dmarc", "_amazonses", "google._domainkey"}
var commonCNAMERecords = []string{"www", "mail", "beta", "dev", "alpha", "private", "developers", "www2", "www3"}

// Zone represents a single dns hostname (ex: example.com or www.example.com) and its associated records.
type Zone struct {
	Name  string
	A     []IP
	MX    []MXRecord
	NS    []Host
	TXT   map[string][]string
	CNAME map[string]string
}

// MXRecord represents the data for a single MX Record entry
type MXRecord struct {
	Priority uint16
	Host     Host
}

// Host represents the data for a single host (name/ips)
type Host struct {
	Name string
	IPs  []IP
}

// IP represents the data for a single IP address
type IP struct {
	Addr  string
	Ptrs  []string
	Owner string
}

// Query performs various DNS queries to build a list of records for a specific domain.
func Query(ctx context.Context, domain string) (z Zone, err error) {

	z.Name = domain

	z.A, err = getARecord(ctx, domain)
	if err != nil {
		return
	}
	z.MX, err = getMXRecords(ctx, domain)
	if err != nil {
		return
	}
	z.NS, err = getNSRecords(ctx, domain)
	if err != nil {
		return
	}
	z.TXT, err = getCommonTXTRecords(ctx, domain)
	if err != nil {
		return
	}
	z.CNAME, err = getCNAMERecords(ctx, domain)
	if err != nil {
		return
	}

	return
}

func getARecord(ctx context.Context, hostname string) (ips []IP, err error) {
	r := net.DefaultResolver
	r.PreferGo = true
	addrs, err := r.LookupHost(ctx, hostname)
	if err != nil {
		return ips, fmt.Errorf("error occurred looking up A Record for %v. %w", hostname, err)
	}

	ips = getIPs(ctx, addrs)
	return
}

func getMXRecords(ctx context.Context, hostname string) (mx []MXRecord, err error) {
	r := net.DefaultResolver
	r.PreferGo = true

	entries, err := r.LookupMX(ctx, hostname)
	if err != nil {
		dnsErr := &net.DNSError{}
		if errors.As(err, &dnsErr) && !dnsErr.IsNotFound {
			return mx, fmt.Errorf("error occurred looking up MX Records for %v. %w", hostname, err)
		}
		return mx, nil
	}

	for _, e := range entries {

		var ips []IP
		ips, err = getARecord(ctx, e.Host)
		if err != nil {
			return
		}

		mx = append(mx, MXRecord{
			Host: Host{
				Name: trimHostname(e.Host),
				IPs:  ips,
			},
			Priority: e.Pref,
		})
	}

	sort.Slice(mx, func(i, j int) bool {
		if mx[i].Priority == mx[j].Priority {
			return mx[i].Host.Name < mx[j].Host.Name
		}
		return mx[i].Priority < mx[j].Priority
	})

	return
}

func getNSRecords(ctx context.Context, hostname string) (ns []Host, err error) {
	r := net.DefaultResolver
	r.PreferGo = true

	entries, err := r.LookupNS(ctx, hostname)
	if err != nil {
		dnsErr := &net.DNSError{}
		if errors.As(err, &dnsErr) && !dnsErr.IsNotFound {
			return ns, fmt.Errorf("error occurred looking up NS Records for %v. %w", hostname, err)
		}
		return ns, nil
	}

	for _, e := range entries {

		var ips []IP
		ips, err = getARecord(ctx, e.Host)
		if err != nil {
			return
		}

		ns = append(ns, Host{
			Name: trimHostname(e.Host),
			IPs:  ips,
		})
	}

	sort.Slice(ns, func(i, j int) bool {
		return ns[i].Name < ns[j].Name
	})

	return
}

func getCommonTXTRecords(ctx context.Context, hostname string) (txts map[string][]string, err error) {
	r := net.DefaultResolver
	r.PreferGo = true

	txts = make(map[string][]string)

	for _, n := range commonTXTRecords {
		if len(n) > 0 {
			n = n + "." + hostname
		} else {
			n = hostname
		}

		entries, err := r.LookupTXT(ctx, n)
		if err != nil {
			// We don't know that these exist, so continue through errors
			continue
		}

		txts[n] = entries
	}

	return
}

func getCNAMERecords(ctx context.Context, hostname string) (cname map[string]string, err error) {
	r := net.DefaultResolver
	r.PreferGo = true

	cname = make(map[string]string)

	for _, n := range commonCNAMERecords {
		name, err := r.LookupCNAME(ctx, n+"."+hostname)
		if err != nil {
			dnsErr := &net.DNSError{}
			if errors.As(err, &dnsErr) && !dnsErr.IsNotFound {
				return cname, fmt.Errorf("error occurred looking up CNAME Records for %v. %w", hostname, err)
			}
			continue
		}

		cname[n] = trimHostname(name)
	}

	return
}

func getIPs(ctx context.Context, addrs []string) (ips []IP) {
	r := net.DefaultResolver
	r.PreferGo = true

	for _, addr := range addrs {
		var names []string
		names, err := r.LookupAddr(ctx, addr)
		if err != nil {
			ips = append(ips, IP{Addr: addr})
			continue
		}
		owner := unknownOwner
		if len(names) > 0 {
			owner = getOwner(names[0])
		}

		for i, n := range names {
			names[i] = trimHostname(n)
		}

		ips = append(ips, IP{
			Addr: addr,
			//TODO: Add IP4 vs IP6?
			Ptrs:  names,
			Owner: owner,
		})
	}

	return
}

func getOwner(name string) string {
	name = strings.TrimSuffix(name, ".")
	nameParts := strings.Split(name, ".")
	partCount := len(nameParts)
	if len(nameParts) < 2 {
		return unknownOwner
	}

	lastIndex := partCount - 1
	if nameParts[lastIndex] == "com" || nameParts[lastIndex] == "net" {
		zoneName := fmt.Sprintf("%v.%v", nameParts[lastIndex-1], nameParts[lastIndex])
		owner, ok := owners[zoneName]
		if !ok {
			return unknownOwner
		}
		return owner
	}
	return unknownOwner
}

func trimHostname(hostname string) string {
	return strings.TrimSuffix(hostname, ".")
}
