package harness

import (
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
)

// The account's identity stays on the thread that classifies: root work
// running beside many classifications still creates root's files, in a
// directory only root can enter.
func TestAsAccountKeepsTheAccountsIdentityOnItsThread(t *testing.T) {
	open, _ := reachTree(t)
	private := t.TempDir() // 0700, root's
	const workers, rounds = 8, 200
	var wg sync.WaitGroup
	errs := make(chan string, workers*rounds)
	for w := range workers {
		wg.Go(func() {
			for range rounds {
				stranger.fakeTimeApplies([]string{filepath.Join(open, "sh")}, "")
			}
		})
		wg.Go(func() {
			for r := range rounds {
				file := filepath.Join(private, strconv.Itoa(w)+"-"+strconv.Itoa(r))
				if err := os.WriteFile(file, nil, 0o600); err != nil {
					errs <- err.Error()
					continue
				}
				info, err := os.Stat(file)
				if err != nil {
					errs <- err.Error()
					continue
				}
				if st, ok := info.Sys().(*syscall.Stat_t); !ok || st.Uid != 0 || st.Gid != 0 {
					errs <- file + " is " + strconv.Itoa(int(st.Uid)) + ":" + strconv.Itoa(int(st.Gid))
				}
			}
		})
	}
	wg.Wait()
	close(errs)
	bad := 0
	for e := range errs {
		if bad == 0 {
			t.Errorf("root's own work ran as the account: %s", e)
		}
		bad++
	}
	if bad > 0 {
		t.Errorf("%d of root's operations ran as the account", bad)
	}
}

// effectiveCaps is the effective capability set of the thread that runs it,
// as /proc/thread-self/status shows it.
func effectiveCaps(t *testing.T) string {
	t.Helper()
	status, err := os.ReadFile("/proc/thread-self/status")
	must(t, err)
	for line := range strings.SplitSeq(string(status), "\n") {
		if caps, ok := strings.CutPrefix(line, "CapEff:"); ok {
			return strings.TrimSpace(caps)
		}
	}
	t.Fatal("no CapEff in /proc/thread-self/status")
	return ""
}

// A thread asAccount emptied of its capabilities is never handed back:
// the goroutines that run after, on whatever threads Go gives them, keep
// root's capabilities.
func TestAsAccountHandsBackNoThreadWithoutCapabilities(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root, whose capabilities asAccount drops")
	}
	want := effectiveCaps(t)
	if strings.Trim(want, "0") == "" {
		t.Skip("the test runs with no capabilities to drop")
	}
	const workers, rounds = 8, 200
	var wg sync.WaitGroup
	bad := make(chan string, workers*rounds)
	for range workers {
		wg.Go(func() {
			for range rounds {
				stranger.asAccount(func() {})
			}
		})
		wg.Go(func() {
			for range rounds {
				runtime.LockOSThread()
				if got := effectiveCaps(t); got != want {
					bad <- got
				}
				runtime.UnlockOSThread()
				runtime.Gosched()
			}
		})
	}
	wg.Wait()
	close(bad)
	if n := len(bad); n > 0 {
		t.Errorf("%d goroutines ran on a thread with capabilities %s, want %s", n, <-bad, want)
	}
}
