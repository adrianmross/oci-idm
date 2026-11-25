package grouprules

import (
	"encoding/json"
	"errors"
	"net/url"
	"os"
	"slices"
	"strings"
	"testing"
)

func sample(t *testing.T) Plan {
	t.Helper()
	p, err := Build(Template{Target: Target{Issuer: "https://example.identity.oraclecloud.com", Scope: "https://api.example.test/read", Profile: "FIXTURE", Region: "test-region"}, Groups: []Group{{Name: "Example readers", Users: []string{"reader@example.test"}}}})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestApplyConvergesAndOnlyAddsReviewedMembers(t *testing.T) {
	p := sample(t)
	var claim, group map[string]any
	var writes []string
	failPatch := true
	run := func(name string, args ...string) ([]byte, error) {
		if name != "oci" || args[0] != "raw-request" {
			t.Fatalf("unexpected command %s %v", name, args)
		}
		values := map[string]string{}
		for i := 1; i < len(args); i += 2 {
			values[args[i]] = args[i+1]
		}
		u, err := url.Parse(values["--target-uri"])
		if err != nil {
			t.Fatal(err)
		}
		if u.Host != "example.identity.oraclecloud.com" || values["--profile"] != "FIXTURE" || values["--region"] != "test-region" {
			t.Fatal("target changed")
		}
		route := strings.TrimPrefix(u.Path, "/admin/v1/")
		method := values["--http-method"]
		var data any
		if method == "GET" {
			var rows []map[string]any
			switch route {
			case "Users":
				if u.Query().Get("filter") != `userName eq "reader@example.test"` {
					t.Fatal("incorrect user selection")
				}
				rows = []map[string]any{{"id": "user1", "userName": "reader@example.test"}}
			case "CustomClaims":
				if claim != nil {
					rows = []map[string]any{claim}
				}
			case "Groups":
				if group != nil {
					rows = []map[string]any{group}
				}
			default:
				t.Fatalf("unexpected read %s", route)
			}
			data = map[string]any{"Resources": rows, "totalResults": len(rows)}
		} else {
			body, err := os.ReadFile(strings.TrimPrefix(values["--request-body"], "file://"))
			if err != nil {
				t.Fatal(err)
			}
			var payload map[string]any
			if err = json.Unmarshal(body, &payload); err != nil {
				t.Fatal(err)
			}
			switch method + " " + route {
			case "POST CustomClaims":
				if payload["allScopes"] != false || payload["tokenType"] != "AT" {
					t.Fatal("unexpected claim policy")
				}
				claim = payload
				claim["id"] = "claim1"
				data = claim
			case "POST Groups":
				if payload["displayName"] != "Example readers" {
					t.Fatal("unexpected group")
				}
				group = payload
				group["id"] = "group1"
				group["members"] = []member{{"existing", "User"}}
				data = group
			case "PATCH Groups/group1":
				if failPatch {
					failPatch = false
					return nil, errors.New("fixture interruption")
				}
				var patch struct {
					Operations []struct {
						Op, Path string
						Value    []member
					}
				}
				if err = json.Unmarshal(body, &patch); err != nil {
					t.Fatal(err)
				}
				if len(patch.Operations) != 1 || patch.Operations[0].Op != "add" || patch.Operations[0].Path != "members" || !slices.Equal(patch.Operations[0].Value, []member{{"user1", "User"}}) {
					t.Fatal("unexpected membership operation")
				}
				group["members"] = append(group["members"].([]member), patch.Operations[0].Value...)
				data = group
			default:
				t.Fatalf("unexpected write %s %s", method, route)
			}
			writes = append(writes, method+" "+route)
		}
		return json.Marshal(map[string]any{"status": "200 OK", "data": data})
	}
	dir := t.TempDir()
	steps, err := Execute(p, dir, run)
	if err == nil || len(steps) != 2 {
		t.Fatalf("missing partial receipt: %v %v", steps, err)
	}
	for range 2 {
		if _, err := Execute(p, dir, run); err != nil {
			t.Fatal(err)
		}
	}
	if !slices.Equal(writes, []string{"POST CustomClaims", "POST Groups", "PATCH Groups/group1"}) {
		t.Fatalf("writes: %v", writes)
	}
}

func TestRefusesConflictingClaimOrAmbiguousLookup(t *testing.T) {
	for name, response := range map[string]string{"ambiguous": `{"totalResults":2,"Resources":[]}`, "malformed": `{}`, "conflict": `{"totalResults":1,"Resources":[{"id":"id1","name":"group_roles","allScopes":true}]}`, "omitted policy": `{"totalResults":1,"Resources":[{"id":"id1","name":"group_roles"}]}`} {
		t.Run(name, func(t *testing.T) {
			p := sample(t)
			p.Groups[0].Users = nil
			_, err := Execute(p, t.TempDir(), func(_ string, a ...string) ([]byte, error) {
				if slices.Contains(a, "POST") || slices.Contains(a, "PATCH") {
					t.Fatal("unexpected write")
				}
				return []byte(`{"status":"200 OK","data":` + response + `}`), nil
			})
			if err == nil {
				t.Fatal("expected closed failure")
			}
		})
	}
}

func TestReviewValidationAndSCIMFilterQuoting(t *testing.T) {
	p := sample(t)
	p.Claim.AllScopes = true
	if _, err := Execute(p, t.TempDir(), func(string, ...string) ([]byte, error) { t.Fatal("unexpected OCI access"); return nil, nil }); err == nil {
		t.Fatal("broadened claim accepted")
	}
	p = sample(t)
	p.Groups[0].Users = []string{`quoted"user@example.test`}
	_, err := Execute(p, t.TempDir(), func(_ string, a ...string) ([]byte, error) {
		if len(a) < 3 {
			t.Fatal(a)
		}
		u, _ := url.Parse(a[2])
		if u.Query().Get("filter") != `userName eq "quoted\"user@example.test"` {
			t.Fatal("misquoted user filter")
		}
		return []byte(`{"status":"200 OK","data":{"totalResults":0,"Resources":[]}}`), nil
	})
	if err == nil {
		t.Fatal("missing user accepted")
	}
}
