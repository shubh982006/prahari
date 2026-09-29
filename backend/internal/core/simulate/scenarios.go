package simulate

import (
	"fmt"
	"time"

	"prahari/internal/domain"
)

var scenarioMeta = map[string]struct{ name, priority, miss string }{
	"A": {"Password spray to finance database exfiltration", "P1", ""},
	"B": {"Phishing to C2 beacon on a workstation", "P2", ""},
	"C": {"MFA fatigue to cloud data theft", "P2", ""},
	"D": {"Ransomware on the file server", "P1", ""},
	"E": {"Low-and-slow credential theft", "P2", "gaps between steps exceed link_window (2h)"},
	"F": {"Entity switching across stages", "P3", "each stage uses a different account and IP"},
}

var scenarios = map[string]func(*gen){"A": scenarioA, "B": scenarioB, "C": scenarioC, "D": scenarioD, "E": scenarioE, "F": scenarioF}

func mins(t time.Time, m int) time.Time { return t.Add(time.Duration(m) * time.Minute) }

func ents(users []string, hosts []string, ips []string, procs ...string) domain.Entities {
	return domain.Entities{Users: users, Hosts: hosts, IPs: ips, Processes: procs}
}

// A: an external IP sprays forty accounts, gets in as priya over VPN, runs
// tooling on her workstation, dumps credentials, moves to the domain
// controller and on to the finance database, stages and exfiltrates.
func scenarioA(g *gen) {
	const ext, drop = "185.220.101.7", "45.133.1.20"
	p := g.u("priya")
	t0 := g.at(9, 12)
	s := func(k int) tag { return tag{"A", k} }
	targets := []string{}
	for _, u := range g.users {
		if u.name != "priya" && len(targets) < 39 {
			targets = append(targets, u.email)
		}
	}
	for i := len(targets); i < 39; i++ {
		targets = append(targets, fmt.Sprintf("user%02d@corp.local", i))
	}
	targets = append(targets[:20], append([]string{p.email}, targets[20:]...)...)
	for i, tgt := range targets {
		g.auth(t0.Add(time.Duration(i*11)*time.Second), tgt, ext, "NL-AMS", "failure", "vpn", false, s(0))
	}
	g.auth(mins(t0, 6), p.email, ext, "NL-AMS", "success", "vpn", false, s(1))
	u, ws := []string{p.email}, p.ws
	g.add(mins(t0, 18), "EDR-PS-ENCODED", domain.SevHigh, ents(u, []string{ws.Name}, []string{ws.IP}, "powershell.exe"),
		map[string]any{"parent": "explorer.exe", "cmdline_len": 3120}, s(2))
	g.add(mins(t0, 20), "EDR-TOOL-DOWNLOAD", domain.SevHigh, ents(u, []string{ws.Name}, []string{ws.IP, ext}, "powershell.exe"),
		map[string]any{"file": "rc.exe", "url": "http://185.220.101.7/rc.exe"}, s(2))
	g.add(mins(t0, 34), "EDR-LSASS-ACCESS", "", ents(u, []string{ws.Name}, []string{ws.IP}, "procdump64.exe"),
		map[string]any{"granted_access": "0x1010"}, s(3))
	g.add(mins(t0, 58), "EDR-RDP-LATERAL", "", ents(u, []string{ws.Name, "dc01"}, []string{ws.IP, hostIP("dc01")}, "mstsc.exe"),
		map[string]any{"EventID": 4624, "LogonType": 10}, s(4))
	g.add(mins(t0, 68), "EDR-DISCOVERY", domain.SevHigh, ents(u, []string{"dc01"}, []string{hostIP("dc01")}, "net.exe"),
		map[string]any{"cmdline": "net group \"Domain Admins\" /domain"}, s(4))
	g.add(mins(t0, 90), "NET-SMB-LATERAL", "", ents(u, []string{"dc01", "fin-db-01"}, []string{hostIP("dc01"), hostIP("fin-db-01")}),
		map[string]any{"share": "ADMIN$"}, s(5))
	g.add(mins(t0, 108), "EDR-ARCHIVE", domain.SevHigh, ents(u, []string{"fin-db-01"}, []string{hostIP("fin-db-01")}, "7z.exe"),
		map[string]any{"archive": "C:\\ProgramData\\q3.7z", "size_mb": 2140}, s(6))
	g.add(mins(t0, 140), "NET-EXFIL-LARGE", domain.SevCritical, ents(nil, []string{"fin-db-01"}, []string{hostIP("fin-db-01"), drop}),
		map[string]any{"bytes_out": 2254857830, "duration_s": 910}, s(7))

	// The over-merge hazard: ten minutes after the attacker leaves dc01, an
	// unrelated admin RDPs to it. The only thing joining the two is dc01, a
	// moderately common entity, so cohesion should call the result fragile.
	if _, ok := g.byName["rohan"]; ok {
		r := g.u("rohan")
		h := tag{group: "noise:hazard"}
		ru := []string{r.email}
		g.add(mins(t0, 100), "EDR-RDP-LATERAL", domain.SevMedium, ents(ru, []string{r.ws.Name, "dc01"}, []string{r.ws.IP, hostIP("dc01")}),
			map[string]any{"EventID": 4624, "LogonType": 10, "ticket": "CHG-20931"}, h)
		for k, rl := range []string{"EDR-SCHED-TASK", "EDR-PS-ENCODED", "EDR-TOOL-DOWNLOAD", "EDR-SCHED-TASK"} {
			g.add(mins(t0, 103+k*3), rl, domain.SevLow, ents(ru, []string{r.ws.Name}, []string{r.ws.IP}),
				map[string]any{"benign": true}, h)
		}
	}
}

// B: a phishing attachment opens a shell, pulls a payload, beacons out and
// starts enumerating from a workstation the CMDB does not know.
func scenarioB(g *gen) {
	const sender, c2 = "193.29.56.14", "91.214.124.9"
	m := g.u("meera")
	t0 := g.at(4, 20)
	s := func(k int) tag { return tag{"B", k} }
	u, ws := []string{m.email}, m.ws
	g.add(t0, "MAIL-PHISH-ATTACH", "", ents(u, nil, []string{sender}), map[string]any{"subject": "Revised appraisal letter", "attachment": "appraisal.docm"}, s(0))
	g.add(mins(t0, 7), "EDR-OFFICE-CHILD", "", ents(u, []string{ws.Name}, []string{ws.IP}, "winword.exe", "powershell.exe"), map[string]any{"parent": "winword.exe"}, s(1))
	g.add(mins(t0, 9), "EDR-TOOL-DOWNLOAD", domain.SevHigh, ents(u, []string{ws.Name}, []string{ws.IP, c2}, "powershell.exe"), map[string]any{"file": "update.dll"}, s(2))
	for k, off := range []int{15, 36, 57} {
		g.add(mins(t0, off), "NET-BEACON", "", ents(nil, []string{ws.Name}, []string{ws.IP, c2}), map[string]any{"interval_s": 1260, "seq": k}, s(3))
	}
	g.add(mins(t0, 72), "EDR-DISCOVERY", "", ents(u, []string{ws.Name}, []string{ws.IP}, "net.exe"), map[string]any{"cmdline": "net user /domain"}, s(4))
	g.add(mins(t0, 84), "NET-SMB-LATERAL", domain.SevMedium, ents(u, []string{ws.Name, "wiki01"}, []string{ws.IP, hostIP("wiki01")}), map[string]any{"share": "C$"}, s(5))
}

// C: push-bombing until rahul accepts, then an OAuth grant, a forwarding rule
// and a bulk download pushed to personal storage. Cloud only, no hosts.
func scenarioC(g *gen) {
	const ext = "102.89.34.12"
	r := g.u("rahul")
	t0 := g.at(13, 20)
	s := func(k int) tag { return tag{"C", k} }
	u, ip := []string{r.email}, []string{ext}
	g.add(t0, "CLOUD-MFA-FATIGUE", "", ents(u, nil, ip), map[string]any{"denials": 14}, s(0))
	g.add(mins(t0, 4), "CLOUD-MFA-FATIGUE", "", ents(u, nil, ip), map[string]any{"denials": 9, "approved": true}, s(0))
	g.add(mins(t0, 12), "CLOUD-NEW-LOCATION", domain.SevHigh, ents(u, nil, ip), map[string]any{"country": "NG"}, s(1))
	g.add(mins(t0, 20), "CLOUD-OAUTH-CONSENT", "", ents(u, nil, ip), map[string]any{"app": "PDF Converter Pro", "scopes": "Mail.ReadWrite Files.Read.All"}, s(2))
	g.add(mins(t0, 31), "CLOUD-INBOX-RULE", "", ents(u, nil, ip), map[string]any{"forward_to": "r.backup.mail@proton.me"}, s(3))
	g.add(mins(t0, 45), "CLOUD-MASS-DOWNLOAD", "", ents(u, nil, ip), map[string]any{"files": 1840, "site": "Sales/Customer Exports"}, s(4))
	g.add(mins(t0, 70), "CLOUD-EXFIL-STORAGE", "", ents(u, nil, ip), map[string]any{"destination": "mega.nz", "mb": 3900}, s(5))
}

// D: an admin account logs in at 02:00 IST from abroad, disables protection on
// the file server, installs a service, clears logs, deletes shadow copies and
// encrypts shares.
func scenarioD(g *gen) {
	const ext = "5.188.206.14"
	v := g.u("vikram")
	t0 := g.at(2, 15)
	s := func(k int) tag { return tag{"D", k} }
	g.auth(t0, v.email, ext, "RO-BUH", "success", "vpn", true, s(0))
	u := []string{v.email}
	fh, fip := []string{"file01"}, []string{hostIP("file01"), ext}
	g.add(mins(t0, 15), "EDR-DEFENDER-OFF", "", ents(u, fh, fip, "powershell.exe"), map[string]any{"cmdline": "Set-MpPreference -DisableRealtimeMonitoring $true"}, s(1))
	g.add(mins(t0, 22), "EDR-NEW-SERVICE", domain.SevHigh, ents(u, fh, fip, "psexesvc.exe"), map[string]any{"service": "PSEXESVC"}, s(2))
	g.add(mins(t0, 30), "EDR-LOG-CLEAR", "", ents(u, fh, fip, "wevtutil.exe"), map[string]any{"log": "Security"}, s(3))
	g.add(mins(t0, 41), "EDR-SHADOW-DELETE", "", ents(u, fh, fip, "vssadmin.exe"), map[string]any{"cmdline": "vssadmin delete shadows /all /quiet"}, s(4))
	for k := 0; k < 3; k++ {
		g.add(mins(t0, 44+k*2), "EDR-RANSOM", "", ents(u, fh, fip, "svch0st.exe"), map[string]any{"files_modified": 4000 + k*2500, "extension": ".lockd"}, s(5))
	}
}

// E: the same kind of chain as A, but each step three hours apart. Every step
// shares anita and her workstation; only the link window keeps them apart.
func scenarioE(g *gen) {
	a := g.u("anita")
	s := func(k int) tag { return tag{"E", k} }
	u, ws := []string{a.email}, a.ws
	g.add(g.at(3.0, 20), "MAIL-PHISH-LINK", "", ents(u, nil, []string{"141.98.10.3"}), map[string]any{"url": "hxxps://sso-corp-local.help/login"}, s(0))
	g.add(g.at(6.3, 20), "EDR-PS-ENCODED", domain.SevHigh, ents(u, []string{ws.Name}, []string{ws.IP}, "powershell.exe"), nil, s(1))
	g.add(g.at(9.7, 20), "EDR-LSASS-ACCESS", "", ents(u, []string{ws.Name}, []string{ws.IP}, "rundll32.exe"), map[string]any{"technique": "comsvcs MiniDump"}, s(2))
	g.add(g.at(13.1, 20), "NET-SMB-LATERAL", "", ents(u, []string{ws.Name, "hr-db-01"}, []string{ws.IP, hostIP("hr-db-01")}), nil, s(3))
	g.add(g.at(16.4, 20), "NET-EXFIL-LARGE", "", ents(nil, []string{"hr-db-01"}, []string{hostIP("hr-db-01"), "64.227.18.9"}), map[string]any{"bytes_out": 740000000}, s(4))
}

// F: four stages, four identities. Nothing is shared between them, so shared
// entity linking cannot see one attack.
func scenarioF(g *gen) {
	t0 := g.at(17, 20)
	s := func(k int) tag { return tag{"F", k} }
	sj, ki, le, mu := g.u("sanjay"), g.u("kiran"), g.u("leela"), g.u("mukesh")
	g.add(t0, "MAIL-PHISH-LINK", "", ents([]string{sj.email}, nil, []string{"196.251.72.4"}), nil, s(0))
	g.add(mins(t0, 34), "EDR-OFFICE-CHILD", "", ents([]string{ki.email}, []string{ki.ws.Name}, []string{ki.ws.IP}, "excel.exe", "cmd.exe"), nil, s(1))
	g.add(mins(t0, 71), "EDR-RDP-LATERAL", "", ents([]string{le.email}, []string{le.ws.Name, "dev-db-01"}, []string{le.ws.IP, hostIP("dev-db-01")}, "mstsc.exe"), nil, s(2))
	g.add(mins(t0, 103), "CLOUD-EXFIL-STORAGE", "", ents([]string{mu.email}, nil, []string{"104.21.33.7"}), map[string]any{"destination": "transfer.sh"}, s(3))
}
