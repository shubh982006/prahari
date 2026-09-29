package detect

import (
	"fmt"
	"testing"
	"time"

	"prahari/internal/domain"
)

var t0 = time.Date(2026, 9, 29, 4, 0, 0, 0, time.UTC) // 09:30 IST

func ev(id string, ts time.Time, user, ip, geo, result string, admin bool) domain.AuthEvent {
	return domain.AuthEvent{EventID: id, TS: ts, Username: user, SrcIP: ip, Geo: geo, Result: result, App: "vpn", IsAdmin: admin}
}

func rules(as []domain.Alert) map[string]int {
	out := map[string]int{}
	for _, a := range as {
		out[a.RuleID]++
	}
	return out
}

func TestDetectors(t *testing.T) {
	cases := []struct {
		name   string
		events func() []domain.AuthEvent
		want   map[string]int
	}{
		{"brute: 10 failures in 5 min", func() []domain.AuthEvent {
			var es []domain.AuthEvent
			for i := 0; i < 10; i++ {
				es = append(es, ev(fmt.Sprint("b", i), t0.Add(time.Duration(i)*20*time.Second), "priya", "10.0.0.1", "", "failure", false))
			}
			return es
		}, map[string]int{"AUTH-BRUTE": 1}},
		{"brute: 9 failures is not enough", func() []domain.AuthEvent {
			var es []domain.AuthEvent
			for i := 0; i < 9; i++ {
				es = append(es, ev(fmt.Sprint("b", i), t0.Add(time.Duration(i)*20*time.Second), "priya", "10.0.0.1", "", "failure", false))
			}
			return es
		}, map[string]int{}},
		{"brute: spread over 10 minutes does not fire", func() []domain.AuthEvent {
			var es []domain.AuthEvent
			for i := 0; i < 10; i++ {
				es = append(es, ev(fmt.Sprint("b", i), t0.Add(time.Duration(i)*time.Minute), "priya", "10.0.0.1", "", "failure", false))
			}
			return es
		}, map[string]int{}},
		{"spray then success from the same IP", func() []domain.AuthEvent {
			var es []domain.AuthEvent
			for i := 0; i < 16; i++ {
				es = append(es, ev(fmt.Sprint("s", i), t0.Add(time.Duration(i)*10*time.Second), fmt.Sprintf("u%d", i), "185.220.101.7", "NL-AMS", "failure", false))
			}
			return append(es, ev("ok", t0.Add(5*time.Minute), "priya", "185.220.101.7", "NL-AMS", "success", false))
		}, map[string]int{"AUTH-SPRAY": 1, "AUTH-SPRAY-SUCCESS": 1}},
		{"many tries per user is brute force, not a spray", func() []domain.AuthEvent {
			var es []domain.AuthEvent
			for i := 0; i < 45; i++ {
				// three tries per user, back to back: by the fifteenth user each
				// earlier one has three tries, so this is guessing, not spraying
				es = append(es, ev(fmt.Sprint("s", i), t0.Add(time.Duration(i)*5*time.Second), fmt.Sprintf("u%d", i/3), "185.220.101.7", "", "failure", false))
			}
			return es
		}, map[string]int{}},
		{"success more than an hour after the spray does not fire", func() []domain.AuthEvent {
			var es []domain.AuthEvent
			for i := 0; i < 15; i++ {
				es = append(es, ev(fmt.Sprint("s", i), t0.Add(time.Duration(i)*10*time.Second), fmt.Sprintf("u%d", i), "185.220.101.7", "", "failure", false))
			}
			return append(es, ev("late", t0.Add(90*time.Minute), "priya", "185.220.101.7", "", "success", false))
		}, map[string]int{"AUTH-SPRAY": 1}},
		{"impossible travel Bengaluru to Amsterdam in an hour", func() []domain.AuthEvent {
			return []domain.AuthEvent{
				ev("1", t0, "priya", "103.21.58.10", "IN-KA", "success", false),
				ev("2", t0.Add(time.Hour), "priya", "185.220.101.7", "NL-AMS", "success", false),
			}
		}, map[string]int{"AUTH-IMPOSSIBLE-TRAVEL": 1}},
		{"Delhi to Mumbai in three hours is possible", func() []domain.AuthEvent {
			return []domain.AuthEvent{
				ev("1", t0, "priya", "1.1.1.1", "IN-DL", "success", false),
				ev("2", t0.Add(3*time.Hour), "priya", "1.1.1.2", "IN-MH", "success", false),
			}
		}, map[string]int{}},
		{"off-hours admin fires once, then it is baseline", func() []domain.AuthEvent {
			night := time.Date(2026, 9, 28, 20, 30, 0, 0, time.UTC) // 02:00 IST
			return []domain.AuthEvent{
				ev("1", night, "vikram", "5.188.206.14", "", "success", true),
				ev("2", night.Add(24*time.Hour), "vikram", "5.188.206.14", "", "success", true),
				ev("3", t0, "vikram", "5.188.206.14", "", "success", true), // 09:30 IST
			}
		}, map[string]int{"AUTH-OFFHOURS-ADMIN": 1}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := rules(Detect("ds_test", c.events()))
			if fmt.Sprint(got) != fmt.Sprint(c.want) {
				t.Fatalf("got %v, want %v", got, c.want)
			}
		})
	}
}

func TestAlertIDsAreDeterministic(t *testing.T) {
	es := []domain.AuthEvent{
		ev("1", t0, "priya", "103.21.58.10", "IN-KA", "success", false),
		ev("2", t0.Add(time.Hour), "priya", "185.220.101.7", "NL-AMS", "success", false),
	}
	a, b := Detect("ds_x", es), Detect("ds_x", []domain.AuthEvent{es[1], es[0]})
	if len(a) != 1 || a[0].ID != b[0].ID {
		t.Fatalf("same events, same IDs regardless of input order: %v %v", a, b)
	}
	if c := Detect("ds_y", es); c[0].ID == a[0].ID {
		t.Fatal("IDs must differ across datasets")
	}
}
