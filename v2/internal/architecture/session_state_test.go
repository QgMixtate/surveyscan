package architecture_test

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// C36.01/C36.04: код центра не зависит от состояния сессии PostgreSQL — иначе он сломается за пулом соединений в
// режиме транзакций (PgBouncer). Разрешено то, что живёт в пределах транзакции: pg_advisory_xact_lock,
// set_config(..., true), SET LOCAL.
func TestNoSessionStateSQL(t *testing.T) {
	// функции — без учёта регистра; ключевые слова SQL — заглавными (как пишется SQL в коде), чтобы не ловить «Listen» в Go
	forbidden := regexp.MustCompile(`(?i:pg_advisory_lock\(|pg_try_advisory_lock\(|pg_advisory_unlock|set_config\([^)]*,\s*false\))|\bLISTEN\s+[a-z_"]|\bUNLISTEN\b|CREATE\s+(TEMP|TEMPORARY)\s+TABLE|\bSET\s+SESSION\b|"SET\s+[a-z_]`)
	var problems []string
	for _, root := range []string{"../../internal", "../../cmd"} {
		_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			raw, e := os.ReadFile(path)
			if e != nil {
				return e
			}
			for i, line := range strings.Split(string(raw), "\n") {
				if forbidden.MatchString(line) {
					problems = append(problems, path+":"+itoa(i+1)+": "+strings.TrimSpace(line))
				}
			}
			return nil
		})
	}
	if len(problems) > 0 {
		t.Fatalf("session-scoped SQL is not allowed (use transaction-scoped locks or messaging.work_leases):\n%s", strings.Join(problems, "\n"))
	}
}

func itoa(n int) string {
	s := ""
	for n > 0 {
		s = string(rune('0'+n%10)) + s
		n /= 10
	}
	return s
}
