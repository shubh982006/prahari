package simulate

import (
	"fmt"

	"prahari/internal/core/detect"
	"prahari/internal/domain"
)

// RuleDef is one detection rule in the simulated estate, with the prior the
// rule_stats table starts from. Priors are Beta(5p, 5(1-p)): a weak belief
// that five analyst verdicts can move.
type RuleDef struct {
	ID, Name, Source, Technique string
	Severity                    domain.Severity
	Prior                       float64
}

var Rules = []RuleDef{
	{"EDR-PS-ENCODED", "Encoded PowerShell command", "edr", "T1059.001", domain.SevHigh, 0.55},
	{"EDR-OFFICE-CHILD", "Office application spawned a shell", "edr", "T1204.002", domain.SevHigh, 0.60},
	{"EDR-NEW-SERVICE", "New service installed", "edr", "T1543.003", domain.SevMedium, 0.30},
	{"EDR-SCHED-TASK", "Scheduled task created", "edr", "T1053.005", domain.SevLow, 0.20},
	{"EDR-LSASS-ACCESS", "Process accessed LSASS memory", "edr", "T1003.001", domain.SevCritical, 0.70},
	{"EDR-RDP-LATERAL", "RDP session from workstation to server", "edr", "T1021.001", domain.SevHigh, 0.60},
	{"EDR-DISCOVERY", "Domain account enumeration", "edr", "T1087.002", domain.SevMedium, 0.35},
	{"EDR-ARCHIVE", "Large archive created with compression utility", "edr", "T1560.001", domain.SevMedium, 0.40},
	{"EDR-RANSOM", "Mass file encryption behaviour", "edr", "T1486", domain.SevCritical, 0.90},
	{"EDR-SHADOW-DELETE", "Volume shadow copies deleted", "edr", "T1490", domain.SevCritical, 0.85},
	{"EDR-DEFENDER-OFF", "Endpoint protection disabled", "edr", "T1685", domain.SevHigh, 0.70},
	{"EDR-LOG-CLEAR", "Security event log cleared", "edr", "T1685.005", domain.SevHigh, 0.75},
	{"EDR-TOOL-DOWNLOAD", "Executable downloaded by script host", "edr", "T1105", domain.SevMedium, 0.40},
	{"EDR-AV-DETECT", "Antivirus detection (quarantined)", "edr", "T1204.002", domain.SevLow, 0.15},
	{"NET-PORTSCAN", "Internal port scan", "network", "T1046", domain.SevMedium, 0.40},
	{"NET-SMB-LATERAL", "SMB admin share access", "network", "T1021.002", domain.SevHigh, 0.50},
	{"NET-BEACON", "Periodic beaconing to rare domain", "network", "T1071.001", domain.SevHigh, 0.50},
	{"NET-DNS-TUNNEL", "DNS query volume anomaly", "network", "T1071.004", domain.SevMedium, 0.30},
	{"NET-EXFIL-LARGE", "Large outbound transfer to unknown host", "network", "T1041", domain.SevHigh, 0.40},
	{"NET-TOR", "Connection to Tor exit node", "network", "T1090.003", domain.SevHigh, 0.60},
	{"NET-TOOL-XFER", "Executable transferred over SMB", "network", "T1570", domain.SevMedium, 0.45},
	{"CLOUD-MFA-FATIGUE", "Repeated MFA push denials", "cloud", "T1621", domain.SevHigh, 0.55},
	{"CLOUD-OAUTH-CONSENT", "OAuth consent to unverified app", "cloud", "T1528", domain.SevHigh, 0.60},
	{"CLOUD-INBOX-RULE", "Inbox rule forwarding to external address", "cloud", "T1564.008", domain.SevHigh, 0.65},
	{"CLOUD-MASS-DOWNLOAD", "Mass download from SharePoint", "cloud", "T1530", domain.SevHigh, 0.50},
	{"CLOUD-EXFIL-STORAGE", "Upload to personal cloud storage", "cloud", "T1567.002", domain.SevHigh, 0.50},
	{"CLOUD-NEW-LOCATION", "Sign-in from new country", "cloud", "T1078.004", domain.SevMedium, 0.30},
	{"MAIL-PHISH-ATTACH", "Phishing attachment delivered", "email", "T1566.001", domain.SevMedium, 0.35},
	{"MAIL-PHISH-LINK", "Phishing link clicked", "email", "T1566.002", domain.SevHigh, 0.50},
	{"MAIL-SPOOF", "Display-name spoofing", "email", "T1566", domain.SevLow, 0.20},
}

var detectorPriors = map[string]float64{
	"AUTH-BRUTE": 0.30, "AUTH-SPRAY": 0.60, "AUTH-SPRAY-SUCCESS": 0.80,
	"AUTH-IMPOSSIBLE-TRAVEL": 0.45, "AUTH-OFFHOURS-ADMIN": 0.35,
}

// AllRuleStats is the starting rule_stats table: every source rule plus the
// five auth detectors.
func AllRuleStats() []domain.RuleStat {
	var out []domain.RuleStat
	for _, r := range Rules {
		out = append(out, prior(r.ID, r.Name, r.Source, r.Technique, r.Prior))
	}
	for _, r := range detect.Rules {
		out = append(out, prior(r.ID, r.Name, "auth", r.Technique, detectorPriors[r.ID]))
	}
	return out
}

func prior(id, name, source, tech string, p float64) domain.RuleStat {
	return domain.RuleStat{RuleID: id, RuleName: name, Source: source, TechniqueID: tech, Alpha: 5 * p, Beta: 5 * (1 - p)}
}

func rule(id string) RuleDef {
	for _, r := range Rules {
		if r.ID == id {
			return r
		}
	}
	panic("simulate: unknown rule " + id)
}

// Host is one machine in the simulated estate. InCMDB hosts make up the
// 40-asset CMDB; the rest are workstations the CMDB does not know about,
// which is realistic and scores as unknown (0.3).
type Host struct {
	Name, IP, Role, Owner string
	Criticality           int
	DataClasses           []string
	InCMDB                bool
}

var Servers = []Host{
	{"dc01", "10.1.0.10", "domain_controller", "it-infra", 10, []string{"credentials"}, true},
	{"dc02", "10.1.0.11", "domain_controller", "it-infra", 10, []string{"credentials"}, true},
	{"vpn-gw01", "10.1.0.5", "vpn_gateway", "it-infra", 7, nil, true},
	{"jump01", "10.1.0.20", "jump_host", "it-infra", 8, []string{"credentials"}, true},
	{"mail01", "10.1.0.25", "mail_server", "it-infra", 7, []string{"pii"}, true},
	{"siem01", "10.1.0.30", "siem", "security", 7, nil, true},
	{"file01", "10.1.0.40", "file_server", "it-infra", 8, []string{"pii"}, true},
	{"bkp-01", "10.1.0.45", "backup_server", "it-infra", 8, nil, true},
	{"dns01", "10.1.0.53", "dns_server", "it-infra", 6, nil, true},
	{"print01", "10.1.0.60", "print_server", "it-infra", 2, nil, true},
	{"wiki01", "10.1.0.70", "intranet_wiki", "it-apps", 4, nil, true},
	{"proxy01", "10.1.0.80", "web_proxy", "it-infra", 5, nil, true},
	{"fin-db-01", "10.2.0.21", "finance_database", "finance-it", 9, []string{"pii", "financial"}, true},
	{"fin-app-01", "10.2.0.22", "finance_app", "finance-it", 8, []string{"financial"}, true},
	{"pay-db-01", "10.2.0.23", "payroll_database", "finance-it", 9, []string{"pii", "financial"}, true},
	{"hr-db-01", "10.2.1.21", "hr_database", "hr-it", 9, []string{"pii"}, true},
	{"hr-app-01", "10.2.1.22", "hr_app", "hr-it", 7, []string{"pii"}, true},
	{"crm-db-01", "10.2.2.21", "crm_database", "sales-it", 8, []string{"pii"}, true},
	{"crm-app-01", "10.2.2.22", "crm_app", "sales-it", 6, []string{"pii"}, true},
	{"web01", "10.4.0.10", "web_server", "platform", 6, nil, true},
	{"web02", "10.4.0.11", "web_server", "platform", 6, nil, true},
	{"api01", "10.4.0.12", "api_gateway", "platform", 7, nil, true},
	{"build01", "10.3.0.10", "build_server", "engineering", 6, []string{"source_code"}, true},
	{"git01", "10.3.0.11", "source_control", "engineering", 8, []string{"source_code"}, true},
	{"dev-db-01", "10.3.0.12", "dev_database", "engineering", 4, nil, true},
	{"vscan01", "10.1.9.20", "vulnerability_scanner", "security", 5, nil, true},
	{"ws-exec-01", "10.1.5.10", "executive_workstation", "office-it", 6, []string{"pii"}, true},
	{"ws-intern-07", "10.1.6.107", "intern_laptop", "interns", 2, nil, true},
}

// Workstation ws-<101+i> belongs to user i; the first twelve are in the CMDB.
const workstationsInCMDB = 12

func Workstation(i int) Host {
	n := 101 + i
	return Host{
		Name: fmt.Sprintf("ws-%d", n), IP: fmt.Sprintf("10.1.%d.%d", 4+n/250, n%250),
		Role: "workstation", Owner: "office-it", Criticality: 3, InCMDB: i < workstationsInCMDB,
	}
}

// CMDB returns the 40 assets the demo starts with.
func CMDB() []domain.Asset {
	var out []domain.Asset
	add := func(h Host) {
		dc := h.DataClasses
		if dc == nil {
			dc = []string{}
		}
		out = append(out, domain.Asset{Hostname: h.Name, Role: h.Role, Criticality: h.Criticality, DataClasses: dc, Owner: h.Owner})
	}
	for _, h := range Servers {
		add(h)
	}
	for i := 0; i < workstationsInCMDB; i++ {
		add(Workstation(i))
	}
	return out
}

func hostIP(name string) string {
	for _, h := range Servers {
		if h.Name == name {
			return h.IP
		}
	}
	panic("simulate: unknown host " + name)
}

// Names for generated users. Scenario actors are pinned at fixed indices so a
// given seed always tells the same story.
var firstNames = []string{
	"aarav", "aditi", "akash", "ananya", "arjun", "bhavna", "chirag", "deepa", "divya", "farhan",
	"gaurav", "harini", "ishaan", "priya", "jaya", "karan", "kavya", "lakshmi", "manish", "meera",
	"mohit", "nandini", "neha", "nikhil", "pooja", "rahul", "rajesh", "ritu", "rohan", "sakshi",
	"sameer", "sanjana", "shreya", "siddharth", "sneha", "sunil", "tanvi", "tarun", "uma", "varun",
	"vikram", "yash", "zoya", "abhishek", "aishwarya", "amit", "anjali", "ashok", "chetan", "dinesh",
	"esha", "gita", "hemant", "irfan", "jatin", "kiran", "lalit", "madhav", "naveen", "om",
	"pallavi", "qadir", "radha", "sachin", "tejas", "usha", "vandana", "wasim", "yamini", "zubin",
	"anita", "sanjay", "leela", "mukesh", "rekha", "suresh", "vinod", "kamala", "deepak", "swati",
}

func userName(i int) string {
	if i < len(firstNames) {
		return firstNames[i]
	}
	return fmt.Sprintf("%s%d", firstNames[i%len(firstNames)], i/len(firstNames))
}
