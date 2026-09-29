package entity

import (
	"reflect"
	"testing"

	"prahari/internal/domain"
)

func TestOneThingOneName(t *testing.T) {
	for _, in := range []string{`CORP\priya`, "priya@corp.local", "PRIYA", " Priya "} {
		if got := NormUser(in); got != "priya@corp.local" {
			t.Errorf("%q → %q", in, got)
		}
	}
	if NormHost("WS-114.corp.local") != "ws-114" || NormIP("::ffff:10.1.0.10") != "10.1.0.10" || NormIP("not-an-ip") != "" {
		t.Fatal("host/ip normalisation")
	}
	if NormProcess(`C:\Windows\System32\WindowsPowerShell\v1.0\PowerShell.exe`) != "powershell.exe" {
		t.Fatal("process normalisation")
	}
}

func TestKeysAreSortedAndDeduplicated(t *testing.T) {
	got := Keys(domain.Entities{Users: []string{"PRIYA", "priya@corp.local"}, Hosts: []string{"DC01"}, IPs: []string{"10.1.0.10", "bogus"}})
	want := []string{"host:dc01", "ip:10.1.0.10", "user:priya@corp.local"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v", got)
	}
}

func TestStoplistNeedsRatioAndMinimum(t *testing.T) {
	var keys [][]string
	for i := 0; i < 100; i++ {
		ks := []string{"ip:proxy"}
		if i < 10 {
			ks = append(ks, "host:rare")
		}
		keys = append(keys, ks)
	}
	idx := Build(keys, 0.05, 20)
	if !idx.Stoplist["ip:proxy"] || idx.Stoplist["host:rare"] {
		t.Fatalf("stop-list: %v", idx.Stoplist)
	}
	if Build(keys[:10], 0.05, 20).Stoplist["ip:proxy"] {
		t.Fatal("a tiny dataset must not stop-list everything")
	}
}
