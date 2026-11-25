package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGroupRulesPlanAndPreviewNeverCallOCI(t *testing.T) {
	old := runCommand
	defer func() { runCommand = old }()
	runCommand = func(string, ...string) ([]byte, error) { t.Fatal("unexpected external command"); return nil, nil }
	dir := t.TempDir()
	in := filepath.Join(dir, "template.json")
	if err := os.WriteFile(in, []byte(`{"target":{"issuer":"https://example.identity.oraclecloud.com","resourceScope":"service.read","ociProfile":"DEMO"},"groups":[{"name":"Example operators","users":["operator@example.test"]}]}`), 0600); err != nil {
		t.Fatal(err)
	}
	var out, diagnostics bytes.Buffer
	if code := Run([]string{"plan", "group-rules", "-f", in}, &out, &diagnostics); code != 0 {
		t.Fatal(diagnostics.String())
	}
	plan := filepath.Join(dir, "plan.json")
	want := out.String()
	if err := os.WriteFile(plan, out.Bytes(), 0600); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if code := Run([]string{"apply", "group-rules", "-f", plan}, &out, &diagnostics); code != 0 || out.String() != want {
		t.Fatalf("preview: %s %s", out.String(), diagnostics.String())
	}
	out.Reset()
	if code := Run([]string{"apply", "group-rules", "-f", plan, "--execute"}, &out, &diagnostics); code == 0 || !strings.Contains(diagnostics.String(), "--confirm") {
		t.Fatalf("unconfirmed apply: %s", diagnostics.String())
	}
	// A confirmed CLI invocation passes the reviewed target to the executor.
	calls := 0
	runCommand = func(name string, args ...string) ([]byte, error) {
		calls++
		if name != "oci" || !strings.Contains(strings.Join(args, " "), "--profile DEMO") || !strings.HasPrefix(args[2], "https://example.identity.oraclecloud.com/admin/v1/Users?") {
			t.Fatalf("unexpected invocation: %s %v", name, args)
		}
		return []byte(`{"status":"200 OK","data":{"totalResults":2,"Resources":[]}}`), nil
	}
	diagnostics.Reset()
	code := Run([]string{"apply", "group-rules", "-f", plan, "--execute", "--confirm", "--out", filepath.Join(dir, "requests")}, &out, &diagnostics)
	if code == 0 || !strings.Contains(diagnostics.String(), "ambiguous") || calls != 1 {
		t.Fatalf("unexpected apply: code=%d calls=%d error=%s", code, calls, diagnostics.String())
	}

}
