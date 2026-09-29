// Package simulate generates a deterministic day of security telemetry for a
// mid-size Indian organisation: authentication events, alerts from four
// other sources, and six planted attack scenarios with hidden ground truth.
//
// Same Params, same output, on any machine: randomness comes only from a PCG
// seeded by Params.Seed, and no map is iterated to produce output.
package simulate

import (
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"sort"
	"strings"
	"time"

	"prahari/internal/core/detect"
	"prahari/internal/domain"
)

var DefaultStart = time.Date(2026, 9, 28, 18, 30, 0, 0, time.UTC) // 00:00 IST, 29 Sep

var AllScenarios = []string{"A", "B", "C", "D", "E", "F"}

type Params struct {
	Seed       int64     `json:"seed"`
	Start      time.Time `json:"start"`
	Hours      int       `json:"hours"`
	Scenarios  []string  `json:"scenarios"`
	NoiseLevel string    `json:"noise_level"`
	Users      int       `json:"users"`
}

func (p Params) WithDefaults() Params {
	if p.Start.IsZero() {
		p.Start = DefaultStart
	}
	p.Start = p.Start.UTC().Truncate(time.Second)
	if p.Hours <= 0 {
		p.Hours = 24
	}
	if p.Scenarios == nil {
		p.Scenarios = AllScenarios
	}
	if p.NoiseLevel == "" {
		p.NoiseLevel = "normal"
	}
	if p.Users <= 0 {
		p.Users = 60
	}
	return p
}

// DatasetID is ds_<IST date>_s<seed>, e.g. ds_20260929_s42.
func DatasetID(p Params) string {
	p = p.WithDefaults()
	id := fmt.Sprintf("ds_%s_s%d", p.Start.In(detect.IST).Format("20060102"), p.Seed)
	if p.Seed < 0 {
		id = fmt.Sprintf("ds_%s_sm%d", p.Start.In(detect.IST).Format("20060102"), -p.Seed)
	}
	return id
}

type Result struct {
	DatasetID  string
	Params     Params
	End        time.Time
	AuthEvents []domain.AuthEvent
	Alerts     []domain.Alert // non-auth sources; auth alerts come from the detectors
	Detector   []domain.Alert // what the detectors raise from AuthEvents
	Truth      domain.Truth
}

// All returns every alert the dataset will hold after ingest, time-ordered.
func (r Result) All() []domain.Alert {
	out := make([]domain.Alert, 0, len(r.Alerts)+len(r.Detector))
	out = append(out, r.Alerts...)
	out = append(out, r.Detector...)
	sort.SliceStable(out, func(i, j int) bool {
		if !out[i].TS.Equal(out[j].TS) {
			return out[i].TS.Before(out[j].TS)
		}
		return out[i].ID < out[j].ID
	})
	return out
}

type tag struct {
	group string // "A".."F" or "noise:<name>"
	step  int
}

type pending struct {
	a   domain.Alert
	tag tag
	seq int
}

type user struct {
	name, email string
	ws          Host
	geo         string
	homeIP      string
	admin       bool
	reserved    bool // scenario actor; kept out of random noise
}

type gen struct {
	p       Params
	dataset string
	rng     *rand.Rand
	users   []user
	byName  map[string]int
	alerts  []pending
	events  []domain.AuthEvent
	evTag   map[string]tag
	seq     int
	evSeq   int
	scale   float64
	bursts  int
}

const (
	proxyIP = "10.1.0.80"
	dnsIP   = "10.1.0.53"
	natIP   = "103.21.58.10" // corporate egress
)

// Reserved scenario actors and their roles.
var reserved = map[string]string{
	"priya": "A", "meera": "B", "rahul": "C", "vikram": "D", "anita": "E",
	"sanjay": "F", "kiran": "F", "leela": "F", "mukesh": "F", "rohan": "hazard",
}

func Generate(p Params) Result {
	p = p.WithDefaults()
	g := &gen{
		p: p, dataset: DatasetID(p),
		rng:   rand.New(rand.NewPCG(uint64(p.Seed), uint64(p.Seed)^0x9e3779b97f4a7c15)),
		evTag: map[string]tag{}, byName: map[string]int{},
	}
	switch p.NoiseLevel {
	case "low":
		g.scale = 0.5
	case "high":
		g.scale = 2
	default:
		g.scale = 1
	}
	g.makeUsers()
	g.backgroundAuth()
	g.chatter()
	g.noiseBursts()
	want := map[string]bool{}
	for _, s := range p.Scenarios {
		want[s] = true
	}
	for _, s := range AllScenarios {
		if want[s] {
			scenarios[s](g)
		}
	}
	return g.finish()
}

func (g *gen) makeUsers() {
	n := g.p.Users
	names := make([]int, 0, n+len(reserved))
	for i := 0; i < n; i++ {
		names = append(names, i)
	}
	for i, nm := range firstNames {
		if _, ok := reserved[nm]; ok && i >= n {
			names = append(names, i)
		}
	}
	geos := []string{"IN-KA", "IN-KA", "IN-KA", "IN-MH", "IN-DL", "IN-TG", "IN-TN"}
	for _, i := range names {
		nm := userName(i)
		u := user{name: nm, email: nm + "@corp.local", ws: Workstation(i), geo: geos[g.rng.IntN(len(geos))],
			homeIP: fmt.Sprintf("49.%d.%d.%d", 36+g.rng.IntN(20), g.rng.IntN(250), 1+g.rng.IntN(250))}
		_, u.reserved = reserved[nm]
		u.admin = nm == "vikram" || nm == "arjun" || nm == "gaurav"
		g.byName[nm] = len(g.users)
		g.users = append(g.users, u)
	}
}

func (g *gen) u(name string) user { return g.users[g.byName[name]] }

// at returns start + h hours scaled to the dataset length, plus jitter.
func (g *gen) at(h float64, jitterMin int) time.Time {
	d := time.Duration(h / 24 * float64(g.p.Hours) * float64(time.Hour))
	if jitterMin > 0 {
		d += time.Duration(g.rng.IntN(jitterMin*60)) * time.Second
	}
	return g.p.Start.Add(d).Truncate(time.Second)
}

func (g *gen) end() time.Time { return g.p.Start.Add(time.Duration(g.p.Hours) * time.Hour) }

func (g *gen) inWindow(t time.Time) bool { return !t.Before(g.p.Start) && t.Before(g.end()) }

func (g *gen) add(ts time.Time, ruleID string, sev domain.Severity, ents domain.Entities, raw map[string]any, t tag) {
	if !g.inWindow(ts) {
		return
	}
	r := rule(ruleID)
	if sev == "" {
		sev = r.Severity
	}
	if raw == nil {
		raw = map[string]any{}
	}
	b, _ := json.Marshal(raw)
	g.seq++
	g.alerts = append(g.alerts, pending{a: domain.Alert{
		DatasetID: g.dataset, TS: ts.UTC(), Source: r.Source, RuleID: r.ID, RuleName: r.Name,
		Severity: sev, TechniqueID: r.Technique, Entities: ents.Normalized(), Raw: b,
	}, tag: t, seq: g.seq})
}

func (g *gen) auth(ts time.Time, username, ip, geo, result, app string, admin bool, t tag) {
	if !g.inWindow(ts) {
		return
	}
	g.evSeq++
	id := fmt.Sprintf("AE-%06d", g.evSeq)
	g.events = append(g.events, domain.AuthEvent{DatasetID: g.dataset, EventID: id, TS: ts.UTC(),
		Username: username, SrcIP: ip, Geo: geo, Result: result, App: app, IsAdmin: admin})
	if t.group != "" {
		g.evTag[id] = t
	}
}

// ---------- background ----------

func (g *gen) backgroundAuth() {
	apps := []string{"o365", "o365", "o365", "vpn", "web", "web"}
	for _, u := range g.users {
		n := 18 + g.rng.IntN(14)
		for k := 0; k < n; k++ {
			h := 3.0 + g.rng.Float64()*13 // 08:30–21:30 IST
			ts := g.at(h, 0)
			app := apps[g.rng.IntN(len(apps))]
			// office logins egress from the NAT of the user's own city, so an
			// ordinary day produces no impossible travel
			ip, geo := officeNAT(u.geo), u.geo
			if app == "vpn" {
				ip = u.homeIP
			}
			if g.rng.Float64() < 0.06 { // typo, then success
				g.auth(ts.Add(-40*time.Second), u.email, ip, geo, "failure", app, false, tag{})
			}
			g.auth(ts, u.email, ip, geo, "success", app, u.admin && app == "vpn", tag{})
		}
	}
	// Two sales staff on VPN egress in Singapore: impossible travel that is not.
	for i, nm := range []string{"tanvi", "varun"} {
		if _, ok := g.byName[nm]; !ok {
			continue
		}
		u := g.u(nm)
		t0 := g.at(5+float64(i)*6, 30)
		g.auth(t0, u.email, u.homeIP, "IN-DL", "success", "vpn", false, tag{group: "noise:travel"})
		g.auth(t0.Add(150*time.Minute), u.email, "103.253.144.7", "SG", "success", "vpn", false, tag{group: "noise:travel"})
	}
	// A night-shift admin: the first off-hours login fires, the rest are baseline.
	if _, ok := g.byName["arjun"]; ok {
		u := g.u("arjun")
		for k := 0; k < 3; k++ {
			g.auth(g.at(0.5+float64(k)*1.5, 20), u.email, hostIP("jump01"), "IN-KA", "success", "rdp", true, tag{group: "noise:nightadmin"})
		}
	}
	// A print service account with a stale password.
	for k := 0; k < int(4*g.scale); k++ {
		t0 := g.at(2+float64(k)*5, 60)
		for j := 0; j < 12; j++ {
			g.auth(t0.Add(time.Duration(j*9)*time.Second), "CORP\\svc-print", hostIP("print01"), "", "failure", "web", false, tag{group: "noise:svcprint"})
		}
	}
}

// chatter is the recurring noise every SOC has: the same rule on the same
// entity all day. Each family becomes one noise_cluster when it stays below
// the stop-list threshold.
func (g *gen) chatter() {
	fam := func(name string, from, to float64, everyMin int, f func(ts time.Time, i int)) {
		step := float64(everyMin) / 60 / g.scale
		i := 0
		for h := from; h < to; h += step {
			f(g.at(h, max(1, everyMin/3)), i)
			i++
		}
		_ = name
	}
	t := func(n string) tag { return tag{group: "noise:" + n} }
	fam("vscan", 1, 22.5, 16, func(ts time.Time, i int) {
		g.add(ts, "NET-PORTSCAN", pick(g.rng, domain.SevLow, domain.SevMedium),
			domain.Entities{Hosts: []string{"vscan01"}, IPs: []string{"10.1.9.20", fmt.Sprintf("10.1.8.%d", 1+g.rng.IntN(250))}},
			map[string]any{"ports_probed": 200 + g.rng.IntN(800), "scanner": "Qualys"}, t("vscan"))
	})
	fam("build-av", 3.5, 14, 8, func(ts time.Time, i int) {
		g.add(ts, "EDR-AV-DETECT", domain.SevLow,
			domain.Entities{Users: []string{"svc-build"}, Hosts: []string{"build01"}, Processes: []string{"msbuild.exe"},
				Hashes: []string{"9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"}},
			map[string]any{"signature": "HackTool:Win64/Mimikatz!pz", "action": "quarantined"}, t("build-av"))
	})
	fam("backup", 0.3, 23.7, 30, func(ts time.Time, i int) {
		g.add(ts, "EDR-NEW-SERVICE", domain.SevLow,
			domain.Entities{Users: []string{"svc-backup"}, Hosts: []string{"bkp-01"}, Processes: []string{"veeamagent.exe"}},
			map[string]any{"service": "VeeamDeploySvc"}, t("backup"))
	})
	fam("web02-beacon", 0.2, 23.8, 21, func(ts time.Time, i int) {
		g.add(ts, "NET-BEACON", domain.SevMedium,
			domain.Entities{Hosts: []string{"web02"}, IPs: []string{"10.4.0.11", "13.107.42.14"}},
			map[string]any{"interval_s": 300, "domain": "telemetry-update.example.net"}, t("web02-beacon"))
	})
	fam("jump-automation", 6, 22, 20, func(ts time.Time, i int) {
		g.add(ts, "EDR-PS-ENCODED", domain.SevMedium,
			domain.Entities{Users: []string{"it-automation"}, Hosts: []string{"jump01"}, Processes: []string{"powershell.exe"}},
			map[string]any{"cmdline_len": 1400 + g.rng.IntN(300)}, t("jump-automation"))
	})
	fam("ap-spoof", 2, 20, 18, func(ts time.Time, i int) {
		g.add(ts, "MAIL-SPOOF", domain.SevLow,
			domain.Entities{Users: []string{"finance-ap@corp.local"}, IPs: []string{fmt.Sprintf("185.%d.%d.%d", 100+g.rng.IntN(50), g.rng.IntN(250), 1+g.rng.IntN(250))}},
			map[string]any{"display_name": "CFO Office"}, t("ap-spoof"))
	})
	fam("dns", 0, 24, 22, func(ts time.Time, i int) {
		g.add(ts, "NET-DNS-TUNNEL", domain.SevLow,
			domain.Entities{Hosts: []string{"dns01"}, IPs: []string{dnsIP}},
			map[string]any{"qps": 900 + g.rng.IntN(400)}, t("dns"))
	})
	if _, ok := g.byName["zoya"]; ok {
		z := g.u("zoya")
		fam("tor-research", 5, 11, 12, func(ts time.Time, i int) {
			g.add(ts, "NET-TOR", domain.SevMedium,
				domain.Entities{Users: []string{z.email}, Hosts: []string{z.ws.Name}, IPs: []string{z.ws.IP, proxyIP, fmt.Sprintf("171.25.193.%d", 20+g.rng.IntN(60))}},
				map[string]any{"note": "threat-intel research VM"}, t("tor-research"))
		})
	}
	fam("wsus", 1, 23, 22, func(ts time.Time, i int) {
		g.add(ts, "EDR-TOOL-DOWNLOAD", domain.SevLow,
			domain.Entities{Users: []string{"system"}, Hosts: []string{"wsus01"}, IPs: []string{"10.1.0.90", proxyIP}, Processes: []string{"wuauclt.exe"}},
			map[string]any{"file": "windows10.0-kb5031356-x64.cab"}, t("wsus"))
	})
	fam("sccm", 0.5, 23.5, 20, func(ts time.Time, i int) {
		g.add(ts, "EDR-SCHED-TASK", domain.SevLow,
			domain.Entities{Users: []string{"svc-sccm"}, Hosts: []string{"sccm01"}, Processes: []string{"ccmexec.exe"}},
			map[string]any{"task": "Configuration Manager Health Evaluation"}, t("sccm"))
	})
	fam("ci-runner", 4, 18, 14, func(ts time.Time, i int) {
		g.add(ts, "EDR-ARCHIVE", domain.SevLow,
			domain.Entities{Users: []string{"svc-ci"}, Hosts: []string{"ci-runner-02"}, Processes: []string{"tar.exe"}},
			map[string]any{"archive": "artifacts.tgz"}, t("ci-runner"))
	})
	fam("mfa-test", 3, 12, 14, func(ts time.Time, i int) {
		g.add(ts, "CLOUD-MFA-FATIGUE", domain.SevMedium,
			domain.Entities{Users: []string{"helpdesk-test@corp.local"}, IPs: []string{"20.192.44.18"}},
			map[string]any{"denials": 3, "note": "helpdesk MFA test account"}, t("mfa-test"))
	})
	fam("phish-sim", 4, 12, 7, func(ts time.Time, i int) {
		g.add(ts, "MAIL-PHISH-LINK", domain.SevLow,
			domain.Entities{Users: []string{"phishsim@corp.local"}, IPs: []string{"52.66.120.8"}},
			map[string]any{"campaign": "Q3 awareness", "platform": "KnowBe4"}, t("phish-sim"))
	})
	fam("smb-backup", 20, 23, 6, func(ts time.Time, i int) {
		g.add(ts, "NET-SMB-LATERAL", domain.SevLow,
			domain.Entities{Users: []string{"svc-backup"}, Hosts: []string{"bkp-01", "file01"}, IPs: []string{hostIP("bkp-01"), hostIP("file01")}},
			map[string]any{"share": "BACKUP$"}, t("backup"))
	})
	// Directory sync on the domain controller runs every evening, which makes
	// dc01 common enough (2–4% of alerts) to be weak evidence for a merge.
	fam("dc-sync", 19.5, 23.9, 6, func(ts time.Time, i int) {
		g.add(ts, "EDR-SCHED-TASK", domain.SevLow,
			domain.Entities{Users: []string{"svc-adsync"}, Hosts: []string{"dc01"}, IPs: []string{hostIP("dc01")}, Processes: []string{"miiserver.exe"}},
			map[string]any{"task": "Azure AD Connect delta sync"}, t("dc-sync"))
	})
	fam("print-tasks", 0.5, 23, 40, func(ts time.Time, i int) {
		g.add(ts, "EDR-SCHED-TASK", domain.SevLow,
			domain.Entities{Users: []string{"system"}, Hosts: []string{"print01"}, Processes: []string{"schtasks.exe"}},
			map[string]any{"task": "\\Microsoft\\Windows\\PrintSpooler\\Cleanup"}, t("print-tasks"))
	})
}

// A burst theme is a coherent piece of benign activity: most real noise is one
// kind of thing happening a few times, not a random walk across the kill chain.
type theme struct {
	w     int
	rules []string
	sev   []domain.Severity
}

var themes = []theme{
	{14, []string{"EDR-PS-ENCODED", "EDR-PS-ENCODED", "EDR-SCHED-TASK"}, []domain.Severity{domain.SevLow, domain.SevLow, domain.SevMedium}},
	{12, []string{"EDR-AV-DETECT"}, []domain.Severity{domain.SevLow}},
	{10, []string{"EDR-NEW-SERVICE", "EDR-SCHED-TASK"}, []domain.Severity{domain.SevLow}},
	{9, []string{"MAIL-SPOOF", "MAIL-PHISH-ATTACH"}, []domain.Severity{domain.SevLow, domain.SevMedium}},
	{8, []string{"CLOUD-NEW-LOCATION"}, []domain.Severity{domain.SevLow, domain.SevMedium}},
	{8, []string{"NET-DNS-TUNNEL"}, []domain.Severity{domain.SevLow}},
	{7, []string{"EDR-TOOL-DOWNLOAD", "NET-BEACON"}, []domain.Severity{domain.SevLow, domain.SevMedium}},
	{6, []string{"EDR-DISCOVERY", "EDR-RDP-LATERAL"}, []domain.Severity{domain.SevLow, domain.SevMedium}},
	{4, []string{"CLOUD-MASS-DOWNLOAD", "EDR-ARCHIVE"}, []domain.Severity{domain.SevLow, domain.SevMedium}},
	// Occasionally benign activity does look like a chain; that is the
	// false-positive load the ranking has to cope with.
	{4, []string{"MAIL-PHISH-ATTACH", "EDR-OFFICE-CHILD", "EDR-PS-ENCODED", "EDR-DISCOVERY", "EDR-TOOL-DOWNLOAD"}, []domain.Severity{domain.SevLow, domain.SevMedium, domain.SevMedium, domain.SevHigh}},
}

var burstServers = []string{"file01", "wiki01", "mail01", "crm-app-01", "dc01", "dc02", "hr-app-01", "git01"}

// Living-off-the-land binaries appear on most EDR alerts. They are common
// enough to be stop-listed, which is exactly why they must be in the data.
var commonProcs = []string{"powershell.exe", "powershell.exe", "powershell.exe", "powershell.exe", "powershell.exe",
	"cmd.exe", "cmd.exe", "cmd.exe", "cmd.exe"}
var rareProcs = []string{"rundll32.exe", "msiexec.exe", "teams.exe", "chrome.exe", "outlook.exe", "code.exe", "java.exe", "python.exe", "7zg.exe", "putty.exe", "notepad++.exe"}

// noiseBursts are short clusters of benign alerts on one user's machine: an
// install, a script, a user clicking things.
func (g *gen) noiseBursts() {
	total := 0
	for _, t := range themes {
		total += t.w
	}
	var pool []int
	for i, u := range g.users {
		if !u.reserved {
			pool = append(pool, i)
		}
	}
	if len(pool) == 0 {
		return
	}
	n := int(230 * g.scale * float64(len(g.users)) / 60)
	for b := 0; b < n; b++ {
		u := g.users[pool[g.rng.IntN(len(pool))]]
		g.bursts++
		grp := tag{group: fmt.Sprintf("noise:burst-%d", g.bursts)}
		// working hours dominate: 08:00–22:00 IST for 85% of bursts
		h := 2.5 + g.rng.Float64()*14
		if g.rng.Float64() < 0.15 {
			h = g.rng.Float64() * 23.5
		}
		ts := g.at(h, 0)
		x := g.rng.IntN(total)
		ti := 0
		for x >= themes[ti].w {
			x -= themes[ti].w
			ti++
		}
		th := themes[ti]
		size := 1 + g.rng.IntN(3) + g.rng.IntN(3) + g.rng.IntN(3)
		server := ""
		if g.rng.Float64() < 0.05 {
			server = burstServers[g.rng.IntN(len(burstServers))]
		}
		for k := 0; k < size; k++ {
			rid := th.rules[g.rng.IntN(len(th.rules))]
			if len(th.rules) == 5 { // the chain-shaped theme walks forward
				rid = th.rules[min(k, len(th.rules)-1)]
			}
			r := rule(rid)
			ents := domain.Entities{Users: []string{u.email}, Hosts: []string{u.ws.Name}, IPs: []string{u.ws.IP}}
			switch r.Source {
			case "cloud", "email":
				ents = domain.Entities{Users: []string{u.email}, IPs: []string{natIP}}
			case "network":
				if rid == "NET-DNS-TUNNEL" {
					ents.IPs = append(ents.IPs, dnsIP)
				} else {
					ents.IPs = append(ents.IPs, proxyIP)
				}
			case "edr":
				if g.rng.Float64() < 0.8 {
					if g.rng.Float64() < 0.9 {
						ents.Processes = []string{commonProcs[g.rng.IntN(len(commonProcs))]}
					} else {
						ents.Processes = []string{rareProcs[g.rng.IntN(len(rareProcs))]}
					}
				}
				if g.rng.Float64() < 0.3 {
					ents.Users = append(ents.Users, "system")
				}
				if g.rng.Float64() < 0.3 {
					ents.IPs = append(ents.IPs, proxyIP)
				}
			}
			if server != "" && r.Source != "cloud" && r.Source != "email" && g.rng.Float64() < 0.5 {
				ents.Hosts = append(ents.Hosts, server)
			}
			g.add(ts, rid, th.sev[g.rng.IntN(len(th.sev))], ents, map[string]any{"benign": true}, grp)
			ts = ts.Add(time.Duration(30+g.rng.IntN(420)) * time.Second)
		}
	}
}

var officeNATs = map[string]string{
	"IN-KA": natIP, "IN-MH": "103.21.59.10", "IN-DL": "103.21.60.10", "IN-TG": "103.21.61.10", "IN-TN": "103.21.62.10",
}

func officeNAT(geo string) string {
	if ip, ok := officeNATs[geo]; ok {
		return ip
	}
	return natIP
}

func pick[T any](r *rand.Rand, xs ...T) T { return xs[r.IntN(len(xs))] }

// ---------- finish ----------

func (g *gen) finish() Result {
	sort.SliceStable(g.alerts, func(i, j int) bool {
		if !g.alerts[i].a.TS.Equal(g.alerts[j].a.TS) {
			return g.alerts[i].a.TS.Before(g.alerts[j].a.TS)
		}
		return g.alerts[i].seq < g.alerts[j].seq
	})
	res := Result{DatasetID: g.dataset, Params: g.p, End: g.end()}
	truth := domain.Truth{DatasetID: g.dataset, Seed: g.p.Seed, Groups: map[string]string{}}
	steps := map[string]map[int][]string{}
	note := func(id string, t tag) {
		if t.group == "" {
			t.group = "noise:single"
		}
		truth.Groups[id] = t.group
		if domain.IsScenarioGroup(t.group) {
			if steps[t.group] == nil {
				steps[t.group] = map[int][]string{}
			}
			steps[t.group][t.step] = append(steps[t.group][t.step], id)
		}
	}
	for i, p := range g.alerts {
		p.a.ID = fmt.Sprintf("ALR-%06d", i+1)
		res.Alerts = append(res.Alerts, p.a)
		note(p.a.ID, p.tag)
	}
	sort.SliceStable(g.events, func(i, j int) bool {
		if !g.events[i].TS.Equal(g.events[j].TS) {
			return g.events[i].TS.Before(g.events[j].TS)
		}
		return g.events[i].EventID < g.events[j].EventID
	})
	res.AuthEvents = g.events
	res.Detector = detect.Detect(g.dataset, g.events)
	for _, a := range res.Detector {
		var raw struct {
			EventIDs []string `json:"event_ids"`
		}
		_ = json.Unmarshal(a.Raw, &raw)
		t := tag{group: "noise:auth"}
		if n := len(raw.EventIDs); n > 0 {
			if et, ok := g.evTag[raw.EventIDs[n-1]]; ok {
				t = et // labelled by the event that fired the rule
			}
		}
		note(a.ID, t)
	}
	want := map[string]bool{}
	for _, s := range g.p.Scenarios {
		want[s] = true
	}
	for _, s := range AllScenarios {
		if !want[s] || steps[s] == nil {
			continue
		}
		meta := scenarioMeta[s]
		ts := domain.TruthScenario{Scenario: s, Name: meta.name, ExpectedPriority: meta.priority, DeliberateMiss: meta.miss}
		var ks []int
		for k := range steps[s] {
			ks = append(ks, k)
		}
		sort.Ints(ks)
		for _, k := range ks {
			ids := steps[s][k]
			sort.Strings(ids)
			ts.Steps = append(ts.Steps, ids)
			ts.AlertIDs = append(ts.AlertIDs, ids...)
		}
		sort.Strings(ts.AlertIDs)
		truth.Scenarios = append(truth.Scenarios, ts)
	}
	res.Truth = truth
	return res
}

// Summary is a one-line description for logs and the CLI.
func (r Result) Summary() string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s: %d auth events, %d source alerts, %d detector alerts, %d scenarios",
		r.DatasetID, len(r.AuthEvents), len(r.Alerts), len(r.Detector), len(r.Truth.Scenarios))
	return b.String()
}
