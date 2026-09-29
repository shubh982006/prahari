package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The zero-setup defaults must land in the backend directory whichever
// directory the process starts in.
func TestDefaultsAreAnchoredAtTheBackendRoot(t *testing.T) {
	backend, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	for _, wd := range []string{backend, filepath.Join(backend, "internal", "core"), filepath.Dir(backend)} {
		t.Run(filepath.Base(wd), func(t *testing.T) {
			t.Chdir(wd)
			c, err := Load("")
			if err != nil {
				t.Fatal(err)
			}
			if _, err := os.Stat(c.AttackBundle); err != nil {
				t.Errorf("attack bundle %q: %v", c.AttackBundle, err)
			}
			if want := filepath.Join(backend, "data"); c.DataDir != want {
				t.Errorf("data dir %q, want %q", c.DataDir, want)
			}
			if want := "file:" + filepath.ToSlash(filepath.Join(backend, "prahari.db")); c.DSN != want {
				t.Errorf("dsn %q, want %q", c.DSN, want)
			}
		})
	}
}

// A binary built from this tree still finds it when started from an
// unrelated directory: the compiled-in source path is the last resort.
func TestRootFromAnUnrelatedDirectory(t *testing.T) {
	backend, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	t.Chdir(t.TempDir())
	if got := Root(); got != backend {
		t.Fatalf("Root() = %q, want %q", got, backend)
	}
}

func TestExplicitPathsAreLeftAlone(t *testing.T) {
	t.Setenv("PRAHARI_DB_DSN", "file:elsewhere.db")
	t.Setenv("PRAHARI_DATA_DIR", "mydata")
	c, err := Load("")
	if err != nil {
		t.Fatal(err)
	}
	if c.DSN != "file:elsewhere.db" || c.DataDir != "mydata" {
		t.Fatalf("explicit values rewritten: %q %q", c.DSN, c.DataDir)
	}
}

func TestPrahariHomeWins(t *testing.T) {
	home := t.TempDir()
	t.Setenv("PRAHARI_HOME", home)
	if Root() != home {
		t.Fatalf("Root() = %q", Root())
	}
	if !strings.HasPrefix(Resolve("data"), home) {
		t.Fatalf("Resolve(data) = %q", Resolve("data"))
	}
}
