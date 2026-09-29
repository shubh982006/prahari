// Package entity normalises alert entities into keys, weights them by rarity
// (IDF) and builds the supernode stop-list.
package entity

import (
	"math"
	"net/netip"
	"path"
	"sort"
	"strings"

	"prahari/internal/domain"
)

// DefaultDomain is appended to bare usernames: PRIYA → priya@corp.local.
const DefaultDomain = "corp.local"

// NormUser maps CORP\priya, priya@corp.local and PRIYA onto one name.
func NormUser(u string) string {
	u = strings.ToLower(strings.TrimSpace(u))
	if u == "" {
		return ""
	}
	if i := strings.IndexByte(u, '\\'); i >= 0 {
		dom, name := u[:i], u[i+1:]
		if name == "" {
			return ""
		}
		if dom == "" || strings.Contains(dom, ".") {
			return name + "@" + dom
		}
		return name + "@" + dom + ".local"
	}
	if strings.Contains(u, "@") {
		return u
	}
	switch u {
	case "system", "local service", "network service", "anonymous logon":
		return u // well-known principals keep their bare name
	}
	return u + "@" + DefaultDomain
}

// NormHost lowercases and strips the DNS suffix: WS-114.corp.local → ws-114.
func NormHost(h string) string {
	h = strings.ToLower(strings.TrimSpace(h))
	if h == "" {
		return ""
	}
	if _, err := netip.ParseAddr(h); err == nil {
		return h
	}
	if i := strings.IndexByte(h, '.'); i > 0 {
		h = h[:i]
	}
	return h
}

// NormIP returns the canonical text form, or "" when the value is not an IP.
func NormIP(s string) string {
	a, err := netip.ParseAddr(strings.TrimSpace(s))
	if err != nil {
		return ""
	}
	return a.Unmap().String()
}

func NormProcess(p string) string {
	p = strings.ToLower(strings.TrimSpace(strings.ReplaceAll(p, "\\", "/")))
	if p == "" {
		return ""
	}
	return path.Base(p)
}

func NormHash(h string) string { return strings.ToLower(strings.TrimSpace(h)) }

// IsExternal reports whether an IP lies outside private, loopback and
// link-local ranges.
func IsExternal(ip string) bool {
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return false
	}
	return !(a.IsPrivate() || a.IsLoopback() || a.IsLinkLocalUnicast() || a.IsUnspecified())
}

// Keys returns the sorted, de-duplicated entity keys of one alert.
func Keys(e domain.Entities) []string {
	seen := map[string]bool{}
	var out []string
	add := func(prefix, v string) {
		if v == "" {
			return
		}
		k := prefix + v
		if !seen[k] {
			seen[k] = true
			out = append(out, k)
		}
	}
	for _, u := range e.Users {
		add("user:", NormUser(u))
	}
	for _, h := range e.Hosts {
		add("host:", NormHost(h))
	}
	for _, ip := range e.IPs {
		add("ip:", NormIP(ip))
	}
	for _, p := range e.Processes {
		add("process:", NormProcess(p))
	}
	for _, h := range e.Hashes {
		add("hash:", NormHash(h))
	}
	sort.Strings(out)
	return out
}

// Normalize rewrites entity values into canonical form in place-order.
func Normalize(e domain.Entities) domain.Entities {
	m := func(in []string, f func(string) string) []string {
		out := make([]string, 0, len(in))
		seen := map[string]bool{}
		for _, v := range in {
			if n := f(v); n != "" && !seen[n] {
				seen[n] = true
				out = append(out, n)
			}
		}
		return out
	}
	return domain.Entities{
		Users:     m(e.Users, NormUser),
		Hosts:     m(e.Hosts, NormHost),
		IPs:       m(e.IPs, NormIP),
		Processes: m(e.Processes, NormProcess),
		Hashes:    m(e.Hashes, NormHash),
	}
}

// Type returns the prefix of a key: "user", "host", ...
func Type(key string) string {
	if i := strings.IndexByte(key, ':'); i > 0 {
		return key[:i]
	}
	return ""
}

func Value(key string) string {
	if i := strings.IndexByte(key, ':'); i > 0 {
		return key[i+1:]
	}
	return key
}

// Index holds per-entity statistics for one run.
type Index struct {
	N        int
	DF       map[string]int
	Weight   map[string]float64
	Stoplist map[string]bool
}

// Build computes document frequency, IDF weight ln(N/df) and the stop-list:
// an entity seen in more than ratio·N alerts (and at least minDF alerts, so a
// tiny dataset does not stop-list everything) never links two alerts.
func Build(keys [][]string, ratio float64, minDF int) *Index {
	idx := &Index{N: len(keys), DF: map[string]int{}, Weight: map[string]float64{}, Stoplist: map[string]bool{}}
	for _, ks := range keys {
		for _, k := range ks {
			idx.DF[k]++
		}
	}
	for k, df := range idx.DF {
		idx.Weight[k] = round4(math.Log(float64(idx.N) / float64(df)))
		if float64(df)/float64(idx.N) > ratio && df >= minDF {
			idx.Stoplist[k] = true
		}
	}
	return idx
}

// SortedStoplist returns the stop-list in a stable order.
func (i *Index) SortedStoplist() []string {
	out := make([]string, 0, len(i.Stoplist))
	for k := range i.Stoplist {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func round4(v float64) float64 { return math.Round(v*1e4) / 1e4 }
