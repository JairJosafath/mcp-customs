package harness

import (
	"os"
	"path/filepath"
	"strconv"
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
