// Package architecture_test guards the E1 module extraction boundaries at source level.
// It is intentionally conservative: new dynamic SQL needs explicit architecture review.
package architecture_test

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

const modulePrefix = "github.com/QgMixtate/surveyscan/v2/internal/modules/"

var writes = regexp.MustCompile(`(?i)\b(?:INSERT\s+INTO|UPDATE|DELETE\s+FROM|MERGE\s+INTO|TRUNCATE(?:\s+TABLE)?|COPY)\s+"?([a-z_][a-z_0-9]*)"?(\s*\.)?`)

func inspect(path, raw string) []string {
	file, err := parser.ParseFile(token.NewFileSet(), path, raw, 0)
	if err != nil {
		return []string{err.Error()}
	}
	var problems []string
	parts := strings.Split(filepath.ToSlash(path), "/")
	owner := ""
	if len(parts) >= 3 && parts[0] == "internal" && parts[1] == "modules" {
		owner = parts[2]
	}
	for _, imp := range file.Imports {
		name, _ := strconv.Unquote(imp.Path.Value)
		if strings.HasPrefix(name, modulePrefix) {
			target := strings.Split(strings.TrimPrefix(name, modulePrefix), "/")
			if strings.HasPrefix(path, "internal/platform/") {
				problems = append(problems, "platform imports domain module")
			} else if owner != "" && target[0] != owner && !(len(target) == 2 && target[1] == "port") {
				problems = append(problems, "foreign module internal import: "+name)
			}
		}
		if strings.HasPrefix(path, "internal/usercli/") || strings.HasPrefix(path, "cmd/surveyscanctl/") || strings.HasPrefix(path, "internal/agent/") || strings.HasPrefix(path, "internal/collector/") {
			if strings.HasPrefix(name, modulePrefix) || strings.HasPrefix(name, "github.com/jackc/pgx") || name == "database/sql" {
				problems = append(problems, "remote client imports database/domain implementation: "+name)
			}
		}
	}
	if owner == "" {
		return problems
	}
	ast.Inspect(file, func(node ast.Node) bool {
		literal, ok := node.(*ast.BasicLit)
		if !ok || literal.Kind != token.STRING {
			return true
		}
		value, _ := strconv.Unquote(literal.Value)
		for _, match := range writes.FindAllStringSubmatch(value, -1) {
			// ON CONFLICT DO UPDATE SET and SELECT FOR UPDATE OF/SKIP/NOWAIT
			// are not relation names. New write targets must be schema-qualified.
			target := strings.ToLower(match[1])
			if target == "set" || target == "of" || target == "skip" || target == "nowait" {
				continue
			}
			if match[2] == "" {
				problems = append(problems, "unqualified SQL write target: "+match[1])
				continue
			}
			if strings.ToLower(match[1]) != owner {
				problems = append(problems, "SQL writes foreign schema: "+match[1])
			}
		}
		return true
	})
	for _, decl := range file.Decls {
		function, ok := decl.(*ast.FuncDecl)
		if !ok || function.Body == nil {
			continue
		}
		ast.Inspect(function.Body, func(node ast.Node) bool {
			call, ok := node.(*ast.CallExpr)
			if !ok || len(call.Args) < 2 {
				return true
			}
			selector, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || (selector.Sel.Name != "Exec" && selector.Sel.Name != "Query" && selector.Sel.Name != "QueryRow") {
				return true
			}
			if literal, ok := call.Args[1].(*ast.BasicLit); ok && literal.Kind == token.STRING {
				return true
			}
			// Two reviewed read templates exist in E1. Pin their AST shape and all
			// constituent strings still pass the foreign-write check above.
			if path == "internal/modules/imports/upload.go" && function.Name.Name == "load" && selector.Sel.Name == "QueryRow" {
				if q, ok := call.Args[1].(*ast.Ident); ok && q.Name == "q" {
					return true
				}
			}
			if path == "internal/modules/access/service.go" && function.Name.Name == "identity" && selector.Sel.Name == "QueryRow" {
				if plus, ok := call.Args[1].(*ast.BinaryExpr); ok && plus.Op == token.ADD {
					a, aOK := plus.X.(*ast.Ident)
					b, bOK := plus.Y.(*ast.Ident)
					if aOK && bOK && a.Name == "identitySQL" && b.Name == "where" {
						return true
					}
				}
			}
			problems = append(problems, "unreviewed dynamic SQL in "+function.Name.Name)
			return true
		})
	}
	return problems
}

func TestModuleBoundaries(t *testing.T) {
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = os.Stat(filepath.Join(root, "go.mod")); err != nil {
		t.Fatal("architecture check must inspect the v2 source root", err)
	}
	count := 0
	err = filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		relative = filepath.ToSlash(relative)
		if entry.IsDir() {
			if strings.HasPrefix(entry.Name(), ".") || relative == "web" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for _, issue := range inspect(relative, string(raw)) {
			t.Error(relative + ": " + issue)
		}
		count++
		return nil
	})
	if err != nil || count < 50 {
		t.Fatal("source inspection incomplete", count, err)
	}
	t.Logf("inspected %d production Go source files", count)
}

func TestGuardRejectsBoundaryCounterexamples(t *testing.T) {
	for _, fixture := range []struct{ path, source string }{
		{"internal/modules/assets/bad.go", `package assets; import "` + modulePrefix + `sources"`},
		{"internal/modules/assets/bad.go", "package assets; const q = `UPDATE sources.sources SET state='active'`"},
		{"internal/modules/assets/bad.go", "package assets; const q = `DELETE FROM \"sources\".sources`"},
		{"internal/modules/assets/bad.go", "package assets; const q = `INSERT INTO users(user_id) VALUES($1)`"},
		{"internal/modules/assets/bad.go", `package assets; func change(){ tx.Exec(ctx, suppliedSQL) }`},
		// C26: модуль cmdb не пишет в активы, ответственность и проекции инвентаризации (только читает их)
		{"internal/modules/cmdb/bad.go", "package cmdb; const q = `UPDATE assets.assets SET merged_into=NULL`"},
		{"internal/modules/cmdb/bad.go", "package cmdb; const q = `INSERT INTO responsibility.responsibility_assignments(tenant_id) VALUES($1)`"},
		{"internal/modules/cmdb/bad.go", "package cmdb; const q = `DELETE FROM inventory.record_facts12`"},
		{"internal/modules/cmdb/bad.go", `package cmdb; import "` + modulePrefix + `assets"`},
		{"internal/platform/bad.go", `package platform; import "` + modulePrefix + `assets/port"`},
		{"internal/usercli/bad.go", `package usercli; import "github.com/jackc/pgx/v5"`},
	} {
		if len(inspect(fixture.path, fixture.source)) == 0 {
			t.Fatal("boundary counterexample accepted", fixture.path, fixture.source)
		}
	}
	for _, query := range []string{"SELECT state FROM sources.sources", "INSERT INTO assets.assets(asset_uid) VALUES($1)", "UPDATE assets.assets SET revision=revision+1"} {
		if problems := inspect("internal/modules/assets/valid.go", fmt.Sprintf("package assets; const q = %q", query)); len(problems) != 0 {
			t.Fatal("owned write or read projection rejected", problems)
		}
	}
}
