// Package attack loads a pinned MITRE ATT&CK STIX bundle and maps techniques
// onto the seven coarse kill-chain stages the engine scores.
//
// The tactic list is read from the bundle, never hard-coded. What is coded is
// the stage each tactic belongs to; a tactic in the bundle that has no stage
// is a load error, so a future ATT&CK release cannot silently drop a tactic.
package attack

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
)

// StageNames are the lane labels for stages 0..6.
var StageNames = [7]string{
	"Recon",
	"Initial Access",
	"Execution & Persistence",
	"Privilege & Credentials",
	"Discovery & Lateral Movement",
	"Collection & C2",
	"Exfiltration & Impact",
}

// stageOfTactic is the design decision (design.md §6.5). ATT&CK v19 split
// Defense Evasion into Stealth and Defense Impairment; both land in stage 3.
// defense-evasion is kept so older bundles still load.
var stageOfTactic = map[string]int{
	"reconnaissance":       0,
	"resource-development": 0,
	"initial-access":       1,
	"execution":            2,
	"persistence":          2,
	"privilege-escalation": 3,
	"credential-access":    3,
	"stealth":              3,
	"defense-impairment":   3,
	"defense-evasion":      3,
	"discovery":            4,
	"lateral-movement":     4,
	"collection":           5,
	"command-and-control":  5,
	"exfiltration":         6,
	"impact":               6,
}

type Tactic struct {
	ShortName string
	Name      string
	Stage     int
}

type Technique struct {
	ID      string
	Name    string
	Tactics []string // display names, in stage order
	Tactic  string   // the tactic that decided the stage
	Stage   int
}

type Catalog struct {
	Version    string
	Hash       string // sha256 of the bundle bytes; goes into config_hash
	tactics    []Tactic
	techniques map[string]Technique
}

type stixObject struct {
	Type            string `json:"type"`
	Name            string `json:"name"`
	ShortName       string `json:"x_mitre_shortname"`
	Version         string `json:"x_mitre_version"`
	Revoked         bool   `json:"revoked"`
	Deprecated      bool   `json:"x_mitre_deprecated"`
	KillChainPhases []struct {
		KillChainName string `json:"kill_chain_name"`
		PhaseName     string `json:"phase_name"`
	} `json:"kill_chain_phases"`
	ExternalReferences []struct {
		SourceName string `json:"source_name"`
		ExternalID string `json:"external_id"`
	} `json:"external_references"`
}

func LoadFile(path string) (*Catalog, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("attack bundle: %w", err)
	}
	defer f.Close()
	return Load(f)
}

func Load(r io.Reader) (*Catalog, error) {
	raw, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(raw)
	var bundle struct {
		Objects []stixObject `json:"objects"`
	}
	if err := json.Unmarshal(raw, &bundle); err != nil {
		return nil, fmt.Errorf("attack bundle: %w", err)
	}
	c := &Catalog{Hash: "sha256:" + hex.EncodeToString(sum[:]), techniques: map[string]Technique{}}
	tacticName := map[string]string{}
	for _, o := range bundle.Objects {
		if o.Revoked || o.Deprecated {
			continue
		}
		switch o.Type {
		case "x-mitre-collection":
			c.Version = o.Version
		case "x-mitre-tactic":
			st, ok := stageOfTactic[o.ShortName]
			if !ok {
				return nil, fmt.Errorf("attack bundle: tactic %q (%s) has no kill-chain stage; add it to stageOfTactic", o.ShortName, o.Name)
			}
			c.tactics = append(c.tactics, Tactic{ShortName: o.ShortName, Name: o.Name, Stage: st})
			tacticName[o.ShortName] = o.Name
		}
	}
	if len(c.tactics) == 0 {
		return nil, fmt.Errorf("attack bundle: no tactics found")
	}
	sort.Slice(c.tactics, func(i, j int) bool {
		if c.tactics[i].Stage != c.tactics[j].Stage {
			return c.tactics[i].Stage < c.tactics[j].Stage
		}
		return c.tactics[i].ShortName < c.tactics[j].ShortName
	})
	for _, o := range bundle.Objects {
		if o.Type != "attack-pattern" || o.Revoked || o.Deprecated {
			continue
		}
		id := ""
		for _, ref := range o.ExternalReferences {
			if ref.SourceName == "mitre-attack" {
				id = ref.ExternalID
			}
		}
		if id == "" {
			continue
		}
		t := Technique{ID: id, Name: o.Name, Stage: -1}
		type ph struct {
			short string
			stage int
		}
		var phases []ph
		for _, p := range o.KillChainPhases {
			if p.KillChainName != "mitre-attack" {
				continue
			}
			st, ok := stageOfTactic[p.PhaseName]
			if !ok {
				return nil, fmt.Errorf("attack bundle: technique %s uses unknown tactic %q", id, p.PhaseName)
			}
			phases = append(phases, ph{p.PhaseName, st})
		}
		if len(phases) == 0 {
			continue
		}
		// A technique listed under several tactics takes its earliest stage:
		// Valid Accounts is Initial Access before it is Persistence.
		sort.Slice(phases, func(i, j int) bool {
			if phases[i].stage != phases[j].stage {
				return phases[i].stage < phases[j].stage
			}
			return phases[i].short < phases[j].short
		})
		t.Stage = phases[0].stage
		t.Tactic = tacticName[phases[0].short]
		for _, p := range phases {
			t.Tactics = append(t.Tactics, tacticName[p.short])
		}
		c.techniques[id] = t
	}
	if c.Version == "" {
		c.Version = "unknown"
	}
	return c, nil
}

// Lookup returns a technique, falling back from a sub-technique to its parent.
func (c *Catalog) Lookup(id string) (Technique, bool) {
	if t, ok := c.techniques[id]; ok {
		return t, true
	}
	if i := strings.IndexByte(id, '.'); i > 0 {
		t, ok := c.techniques[id[:i]]
		return t, ok
	}
	return Technique{}, false
}

// StageOf is the function the engine receives; it never sees the catalog.
func (c *Catalog) StageOf(id string) (int, bool) {
	t, ok := c.Lookup(id)
	if !ok {
		return 0, false
	}
	return t.Stage, true
}

func (c *Catalog) TacticsForStage(stage int) []string {
	var out []string
	for _, t := range c.tactics {
		if t.Stage == stage {
			out = append(out, t.Name)
		}
	}
	return out
}

func (c *Catalog) Tactics() []Tactic { return append([]Tactic(nil), c.tactics...) }

func (c *Catalog) Len() int { return len(c.techniques) }
