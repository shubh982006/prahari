// Package detect implements the five sliding-window authentication detectors
// (problem #22). A Detector is fed events in timestamp order and returns the
// alerts each event raises. It is deterministic: alert IDs derive from the
// dataset, the rule and the triggering event.
package detect

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"math"
	"sort"
	"time"

	"prahari/internal/core/entity"
	"prahari/internal/domain"
)

var IST = time.FixedZone("IST", 5*3600+1800)

type Rule struct {
	ID, Name, Technique string
	Severity            domain.Severity
}

var (
	RuleBrute         = Rule{"AUTH-BRUTE", "Repeated failed logins for one account", "T1110.001", domain.SevMedium}
	RuleSpray         = Rule{"AUTH-SPRAY", "Password spray from one source IP", "T1110.003", domain.SevHigh}
	RuleSpraySuccess  = Rule{"AUTH-SPRAY-SUCCESS", "Successful login from spraying IP", "T1078", domain.SevCritical}
	RuleImpossible    = Rule{"AUTH-IMPOSSIBLE-TRAVEL", "Impossible travel between successful logins", "T1078", domain.SevHigh}
	RuleOffHoursAdmin = Rule{"AUTH-OFFHOURS-ADMIN", "Privileged login outside business hours", "T1078.002", domain.SevMedium}
	Rules             = []Rule{RuleBrute, RuleSpray, RuleSpraySuccess, RuleImpossible, RuleOffHoursAdmin}
)

const (
	bruteWindow     = 5 * time.Minute
	bruteThreshold  = 10
	sprayWindow     = 10 * time.Minute
	sprayUsers      = 15
	sprayMaxTries   = 2
	spraySuccessTTL = 60 * time.Minute
	travelKMH       = 900.0
	travelMinKM     = 500.0
	baselineWindow  = 7 * 24 * time.Hour
)

// Geo centroids for impossible-travel. Unknown codes are skipped rather than
// guessed.
var geo = map[string][2]float64{
	"IN-DL": {28.61, 77.21}, "IN-MH": {19.08, 72.88}, "IN-KA": {12.97, 77.59},
	"IN-TN": {13.08, 80.27}, "IN-TG": {17.39, 78.49}, "IN-WB": {22.57, 88.36},
	"IN-GJ": {23.02, 72.57}, "IN-HR": {28.46, 77.03}, "IN-UP": {26.85, 80.95},
	"NL-AMS": {52.37, 4.90}, "DE-FRA": {50.11, 8.68}, "GB-LON": {51.51, -0.13},
	"FR-PAR": {48.86, 2.35}, "US-NY": {40.71, -74.01}, "US-CA": {37.77, -122.42},
	"US-VA": {38.95, -77.45}, "SG": {1.35, 103.82}, "AE-DXB": {25.20, 55.27},
	"RU-MOW": {55.76, 37.62}, "CN-BJ": {39.90, 116.40}, "BR-SP": {-23.55, -46.63},
	"JP-TYO": {35.68, 139.69}, "AU-SYD": {-33.87, 151.21}, "RO-BUH": {44.43, 26.10},
}

func Known(geoCode string) bool { _, ok := geo[geoCode]; return ok }

type stamped struct {
	ts    time.Time
	other string // the IP for per-user windows, the user for per-IP windows
	id    string
}

type lastLogin struct {
	ts  time.Time
	geo string
	ip  string
	id  string
}

type Detector struct {
	dataset       string
	lastTS        time.Time
	failsByUser   map[string][]stamped
	failsByIP     map[string][]stamped
	sprayedAt     map[string]time.Time
	sprayHitFired map[string]bool
	lastSuccess   map[string]lastLogin
	lastOffHours  map[string]time.Time
}

func New(datasetID string) *Detector {
	return &Detector{
		dataset:       datasetID,
		failsByUser:   map[string][]stamped{},
		failsByIP:     map[string][]stamped{},
		sprayedAt:     map[string]time.Time{},
		sprayHitFired: map[string]bool{},
		lastSuccess:   map[string]lastLogin{},
		lastOffHours:  map[string]time.Time{},
	}
}

// Late reports whether ev is earlier than the last event fed.
func (d *Detector) Late(ev domain.AuthEvent) bool { return ev.TS.Before(d.lastTS) }

// Feed processes one event. Events must arrive in timestamp order; a late
// event is still evaluated against current state.
func (d *Detector) Feed(ev domain.AuthEvent) []domain.Alert {
	if ev.TS.After(d.lastTS) {
		d.lastTS = ev.TS
	}
	user := entity.NormUser(ev.Username)
	ip := entity.NormIP(ev.SrcIP)
	var out []domain.Alert
	if ev.Result == "failure" {
		out = append(out, d.brute(ev, user, ip)...)
		out = append(out, d.spray(ev, user, ip)...)
		return out
	}
	out = append(out, d.spraySuccess(ev, user, ip)...)
	out = append(out, d.travel(ev, user, ip)...)
	out = append(out, d.offHours(ev, user, ip)...)
	d.lastSuccess[user] = lastLogin{ev.TS, ev.Geo, ip, ev.EventID}
	return out
}

// Detect runs every detector over a batch, sorting it first.
func Detect(datasetID string, events []domain.AuthEvent) []domain.Alert {
	sorted := append([]domain.AuthEvent(nil), events...)
	sort.SliceStable(sorted, func(i, j int) bool {
		if !sorted[i].TS.Equal(sorted[j].TS) {
			return sorted[i].TS.Before(sorted[j].TS)
		}
		return sorted[i].EventID < sorted[j].EventID
	})
	d := New(datasetID)
	var out []domain.Alert
	for _, ev := range sorted {
		out = append(out, d.Feed(ev)...)
	}
	return out
}

func prune(xs []stamped, now time.Time, w time.Duration) []stamped {
	i := 0
	for i < len(xs) && now.Sub(xs[i].ts) > w {
		i++
	}
	return xs[i:]
}

func (d *Detector) brute(ev domain.AuthEvent, user, ip string) []domain.Alert {
	xs := append(prune(d.failsByUser[user], ev.TS, bruteWindow), stamped{ev.TS, ip, ev.EventID})
	d.failsByUser[user] = xs
	if len(xs) < bruteThreshold {
		return nil
	}
	ips := uniq(func(yield func(string)) {
		for _, x := range xs {
			yield(x.other)
		}
	})
	ids := eventIDs(xs)
	d.failsByUser[user] = nil
	return []domain.Alert{d.alert(RuleBrute, ev,
		domain.Entities{Users: []string{user}, IPs: ips},
		map[string]any{"failures": len(xs), "window": "5m", "event_ids": ids})}
}

func (d *Detector) spray(ev domain.AuthEvent, user, ip string) []domain.Alert {
	if ip == "" {
		return nil
	}
	xs := append(prune(d.failsByIP[ip], ev.TS, sprayWindow), stamped{ev.TS, user, ev.EventID})
	d.failsByIP[ip] = xs
	tries := map[string]int{}
	maxTries := 0
	for _, x := range xs {
		tries[x.other]++
		maxTries = max(maxTries, tries[x.other])
	}
	if len(tries) < sprayUsers || maxTries > sprayMaxTries {
		return nil
	}
	targets := make([]string, 0, len(tries))
	for u := range tries {
		targets = append(targets, u)
	}
	sort.Strings(targets)
	d.sprayedAt[ip] = ev.TS
	d.failsByIP[ip] = nil
	// Targets go in raw, not entities: victims of a spray are not actors, and
	// linking on them would fuse every targeted user's day into the incident.
	return []domain.Alert{d.alert(RuleSpray, ev,
		domain.Entities{IPs: []string{ip}},
		map[string]any{"distinct_users": len(targets), "targets": targets, "window": "10m", "event_ids": eventIDs(xs)})}
}

func (d *Detector) spraySuccess(ev domain.AuthEvent, user, ip string) []domain.Alert {
	at, ok := d.sprayedAt[ip]
	if !ok || ev.TS.Sub(at) > spraySuccessTTL || ev.TS.Before(at) {
		return nil
	}
	key := ip + "|" + user
	if d.sprayHitFired[key] {
		return nil
	}
	d.sprayHitFired[key] = true
	return []domain.Alert{d.alert(RuleSpraySuccess, ev,
		domain.Entities{Users: []string{user}, IPs: []string{ip}},
		map[string]any{"app": ev.App, "geo": ev.Geo, "sprayed_at": at.UTC().Format(time.RFC3339), "event_ids": []string{ev.EventID}})}
}

func (d *Detector) travel(ev domain.AuthEvent, user, ip string) []domain.Alert {
	prev, ok := d.lastSuccess[user]
	if !ok || prev.geo == "" || ev.Geo == "" || prev.geo == ev.Geo {
		return nil
	}
	a, okA := geo[prev.geo]
	b, okB := geo[ev.Geo]
	if !okA || !okB {
		return nil
	}
	km := haversine(a, b)
	hours := ev.TS.Sub(prev.ts).Hours()
	if km < travelMinKM {
		return nil
	}
	if hours > 0 && km/hours <= travelKMH {
		return nil
	}
	speed := math.Inf(1)
	if hours > 0 {
		speed = km / hours
	}
	// Only the new login's source is an entity: the previous IP is often a
	// shared office NAT, and linking on it would join unrelated users.
	ips := uniq(func(yield func(string)) { yield(ip) })
	raw := map[string]any{"from": prev.geo, "to": ev.Geo, "from_ip": prev.ip, "km": math.Round(km),
		"minutes": math.Round(ev.TS.Sub(prev.ts).Minutes()), "event_ids": []string{prev.id, ev.EventID}}
	if !math.IsInf(speed, 1) {
		raw["kmh"] = math.Round(speed)
	}
	return []domain.Alert{d.alert(RuleImpossible, ev, domain.Entities{Users: []string{user}, IPs: ips}, raw)}
}

func (d *Detector) offHours(ev domain.AuthEvent, user, ip string) []domain.Alert {
	if !ev.IsAdmin {
		return nil
	}
	h := ev.TS.In(IST).Hour()
	if h >= 5 {
		return nil
	}
	last, seen := d.lastOffHours[user]
	d.lastOffHours[user] = ev.TS
	if seen && ev.TS.Sub(last) <= baselineWindow {
		return nil // this admin routinely works nights; within baseline
	}
	return []domain.Alert{d.alert(RuleOffHoursAdmin, ev,
		domain.Entities{Users: []string{user}, IPs: []string{ip}},
		map[string]any{"ist_time": ev.TS.In(IST).Format("15:04"), "app": ev.App, "event_ids": []string{ev.EventID}})}
}

func (d *Detector) alert(r Rule, ev domain.AuthEvent, ents domain.Entities, raw map[string]any) domain.Alert {
	h := sha256.Sum256([]byte(d.dataset + "|" + r.ID + "|" + ev.EventID))
	rawJSON, _ := json.Marshal(raw)
	return domain.Alert{
		DatasetID:   d.dataset,
		ID:          "ALR-A" + hex.EncodeToString(h[:])[:10],
		TS:          ev.TS.UTC(),
		Source:      "auth",
		RuleID:      r.ID,
		RuleName:    r.Name,
		Severity:    r.Severity,
		TechniqueID: r.Technique,
		Entities:    ents.Normalized(),
		Raw:         rawJSON,
	}
}

func eventIDs(xs []stamped) []string {
	out := make([]string, len(xs))
	for i, x := range xs {
		out[i] = x.id
	}
	return out
}

func uniq(seq func(func(string))) []string {
	seen := map[string]bool{}
	var out []string
	seq(func(s string) {
		if s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	})
	return out
}

func haversine(a, b [2]float64) float64 {
	const r = 6371.0
	rad := math.Pi / 180
	dLat := (b[0] - a[0]) * rad
	dLon := (b[1] - a[1]) * rad
	s := math.Sin(dLat/2)*math.Sin(dLat/2) + math.Cos(a[0]*rad)*math.Cos(b[0]*rad)*math.Sin(dLon/2)*math.Sin(dLon/2)
	return 2 * r * math.Asin(math.Sqrt(s))
}
