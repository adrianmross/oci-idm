package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestMain(m *testing.M) {
	runCommand = func(name string, args ...string) ([]byte, error) {
		return nil, errors.New("oci-context unavailable in test")
	}
	os.Exit(m.Run())
}

func TestVersion(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := Run([]string{"version"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("Run failed with %d: %s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "dev") {
		t.Fatalf("unexpected version output: %q", stdout.String())
	}
}

func TestPlanJSON(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := Run([]string{
		"plan",
		"--service", "obp",
		"--issuer", "https://idcs-example.identity.oraclecloud.com",
		"--platform", "https://example-oabcs.blockchain.ocp.oraclecloud.com:7443/restproxy",
		"--base-app-name", "example-obp_APPID",
		"--include", "user,service",
	}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("Run failed with %d: %s", code, stderr.String())
	}

	var payload map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &payload); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if payload["schemaVersion"] != "oci-idm.plan.v1" {
		t.Fatalf("unexpected schema version: %#v", payload["schemaVersion"])
	}
	apps := payload["apps"].([]any)
	if len(apps) != 2 {
		t.Fatalf("expected 2 apps, got %d", len(apps))
	}
}

func TestExportOBPEECP(t *testing.T) {
	var server *httptest.Server
	server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/.well-known/openid-configuration" {
			http.NotFound(w, request)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"issuer":"` + server.URL + `","jwks_uri":"` + server.URL + `/keys","authorization_endpoint":"` + server.URL + `/authorize","token_endpoint":"` + server.URL + `/token","end_session_endpoint":"` + server.URL + `/logout"}`))
	}))
	defer server.Close()
	previousClient := oidcHTTPClient
	oidcHTTPClient = server.Client()
	defer func() { oidcHTTPClient = previousClient }()

	policyPath := filepath.Join(t.TempDir(), "policy.json")
	policy := `{
  "provider":{"providerName":"IDCS_AUTOMATION","providerType":"IDCS","scope":"openid profile offline_access","clientClaimName":"client_name","clientClaimValue":"cp-client","groupsClaimName":"group_roles","userClaimName":"user_displayname"},
  "groupMappings":{"bpmAdminGroup":"bpm","walletSuperAdminGroup":"wallet-super","instanceAdminGroup":"instance-admin","instanceOperatorGroup":"instance-operator","instanceApiClientGroup":"instance-client","walletOrgAdminGroup":"wallet-org-admin","walletOrgUserGroup":"wallet-org-user","daSuperAdminGroup":"da-super","daTokenAdminGroup":"da-token","daDeployerGroup":"da-deployer","daApproverGroup":"da-approver"},
  "secretRefs":{"providerClientSecret":"secret://obp/idcs/control-plane-client-secret"}
}`
	if err := os.WriteFile(policyPath, []byte(policy), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := Run([]string{"export", "--shape", "obpee-cp", "--domain", server.URL, "--app", "cp-client-id", "--control-plane-url", "https://cp.example.test:7443", "--policy", policyPath}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("export failed with %d: %s", code, stderr.String())
	}
	var output struct {
		SchemaVersion string `json:"schemaVersion"`
		Target        struct {
			RedirectURI string `json:"redirectUri"`
		} `json:"target"`
		IdentityDomain struct {
			Issuer        string `json:"issuer"`
			ApplicationID string `json:"applicationId"`
		} `json:"identityDomain"`
		Request map[string]string `json:"request"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &output); err != nil {
		t.Fatalf("invalid export JSON: %v\n%s", err, stdout.String())
	}
	if output.SchemaVersion != "oci-idm.obpee-cp.v1" || output.IdentityDomain.Issuer != server.URL || output.IdentityDomain.ApplicationID != "cp-client-id" {
		t.Fatalf("unexpected export: %+v", output)
	}
	if output.Target.RedirectURI != "https://cp.example.test:7443/api/v1/auth/provider/code" || output.Request["providerClientId"] != "cp-client-id" {
		t.Fatalf("missing rendered Control Plane fields: %+v", output)
	}
	if _, found := output.Request["providerClientSecret"]; found || strings.Contains(stdout.String(), `"providerClientSecret":"`) {
		t.Fatalf("export included a client secret value: %s", stdout.String())
	}
}

func TestPlanRejectsUnknownInclude(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := Run([]string{
		"plan",
		"--issuer", "https://idcs-example.identity.oraclecloud.com",
		"--scope", "https://service.example.com/.default",
		"--include", "bad",
	}, &stdout, &stderr)
	if code == 0 {
		t.Fatal("expected failure")
	}
	if stderr.Len() == 0 {
		t.Fatal("expected stderr output")
	}
}

func TestPlanUsesOCIContextDefaults(t *testing.T) {
	restore := mockOCIContext(t, map[string]string{
		"export -f json":            `{"name":"oabcs1","profile":"OABCS1","region":"us-sanjose-1"}`,
		"paths -o json":             `{"oci_config_path":"/tmp/oci-config"}`,
		"auth service list -o json": `[{"name":"obp","issuer":"https://idcs-example.identity.oraclecloud.com","scope":"https://example-oabcs.blockchain.ocp.oraclecloud.com:7443/restproxy"}]`,
	})
	defer restore()

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := Run([]string{
		"plan",
		"--service", "obp",
		"--resource-app-id", "resource-app-id",
		"--include", "jwt-service",
		"--format", "json",
	}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("Run failed with %d: %s", code, stderr.String())
	}

	var payload struct {
		Target struct {
			Issuer        string `json:"issuer"`
			Platform      string `json:"platform"`
			Scope         string `json:"scope"`
			OCIContext    string `json:"ociContext"`
			OCIProfile    string `json:"ociProfile"`
			OCIConfigPath string `json:"ociConfigPath"`
			OCIRegion     string `json:"ociRegion"`
		} `json:"target"`
		Apps []struct {
			OCICreateCommand string `json:"ociCreateCommand"`
		} `json:"apps"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &payload); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, stdout.String())
	}
	if payload.Target.OCIContext != "oabcs1" || payload.Target.OCIProfile != "OABCS1" || payload.Target.OCIConfigPath != "/tmp/oci-config" || payload.Target.OCIRegion != "us-sanjose-1" {
		t.Fatalf("missing oci-context defaults: %+v", payload.Target)
	}
	if payload.Target.Issuer != "https://idcs-example.identity.oraclecloud.com" || payload.Target.Scope == "" || payload.Target.Platform == "" {
		t.Fatalf("missing token service defaults: %+v", payload.Target)
	}
	if len(payload.Apps) != 1 || !strings.Contains(payload.Apps[0].OCICreateCommand, "--profile 'OABCS1'") || !strings.Contains(payload.Apps[0].OCICreateCommand, "--config-file '/tmp/oci-config'") || !strings.Contains(payload.Apps[0].OCICreateCommand, "--region 'us-sanjose-1'") {
		t.Fatalf("generated command did not include context defaults: %+v", payload.Apps)
	}
}

func TestDefaultsText(t *testing.T) {
	restore := mockOCIContext(t, map[string]string{
		"export -f json":            `{"name":"oabcs1","profile":"OABCS1","region":"us-sanjose-1"}`,
		"paths -o json":             `{"oci_config_path":"/tmp/oci-config"}`,
		"auth service list -o json": `[{"name":"obp","issuer":"https://idcs-example.identity.oraclecloud.com","scope":"https://example-oabcs.blockchain.ocp.oraclecloud.com:7443/restproxy"}]`,
	})
	defer restore()

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := Run([]string{"defaults", "-o", "text"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("Run failed with %d: %s", code, stderr.String())
	}
	out := stdout.String()
	for _, want := range []string{"context: oabcs1", "profile: OABCS1", "issuer: https://idcs-example.identity.oraclecloud.com"} {
		if !strings.Contains(out, want) {
			t.Fatalf("expected %q in output:\n%s", want, out)
		}
	}
}

func TestGetDefaultsText(t *testing.T) {
	restore := mockOCIContext(t, map[string]string{
		"export -f json":            `{"name":"oabcs1","profile":"OABCS1","region":"us-sanjose-1"}`,
		"paths -o json":             `{"oci_config_path":"/tmp/oci-config"}`,
		"auth service list -o json": `[{"name":"obp","issuer":"https://idcs-example.identity.oraclecloud.com","scope":"https://example-oabcs.blockchain.ocp.oraclecloud.com:7443/restproxy"}]`,
	})
	defer restore()

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := Run([]string{"get", "defaults", "-o", "text"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("Run failed with %d: %s", code, stderr.String())
	}
	out := stdout.String()
	for _, want := range []string{"context: oabcs1", "profile: OABCS1", "issuer: https://idcs-example.identity.oraclecloud.com"} {
		if !strings.Contains(out, want) {
			t.Fatalf("expected %q in output:\n%s", want, out)
		}
	}
}

func TestGetDefaultsUsesCurrentService(t *testing.T) {
	restore := mockOCIContext(t, map[string]string{
		"export -f json":            `{"name":"oabcs1","profile":"OABCS1","region":"us-sanjose-1","current_service":"hebe-obp-user"}`,
		"paths -o json":             `{"oci_config_path":"/tmp/oci-config"}`,
		"auth service list -o json": `[{"name":"hebe-obp-user","issuer":"https://idcs-example.identity.oraclecloud.com","scope":"https://example-oabcs.blockchain.ocp.oraclecloud.com:7443/restproxy"}]`,
	})
	defer restore()

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := Run([]string{"get", "defaults", "-o", "text"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("Run failed with %d: %s", code, stderr.String())
	}
	out := stdout.String()
	for _, want := range []string{"service: hebe-obp-user", "issuer: https://idcs-example.identity.oraclecloud.com"} {
		if !strings.Contains(out, want) {
			t.Fatalf("expected %q in output:\n%s", want, out)
		}
	}
}

func TestDiscoverText(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := Run([]string{
		"discover",
		"--issuer", "https://idcs-example.identity.oraclecloud.com",
		"--query", "example",
		"--app-id", "resource-app-id",
		"--profile", "DEFAULT",
		"--format", "text",
	}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("Run failed with %d: %s", code, stderr.String())
	}
	out := stdout.String()
	for _, want := range []string{"search-apps", "get-resource-app", "search-grants-for-resource-app", "--profile 'DEFAULT'"} {
		if !strings.Contains(out, want) {
			t.Fatalf("expected %q in output:\n%s", want, out)
		}
	}
}

func TestGetServiceAppsText(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := Run([]string{
		"get", "service-apps",
		"--issuer", "https://idcs-example.identity.oraclecloud.com",
		"--query", "example",
		"--app-id", "resource-app-id",
		"--profile", "DEFAULT",
		"-o", "text",
	}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("Run failed with %d: %s", code, stderr.String())
	}
	out := stdout.String()
	for _, want := range []string{"search-apps", "get-resource-app", "search-grants-for-resource-app", "--profile 'DEFAULT'"} {
		if !strings.Contains(out, want) {
			t.Fatalf("expected %q in output:\n%s", want, out)
		}
	}
}

func TestGetDomainsUsesOCIContextAndEnvironmentDefaults(t *testing.T) {
	t.Setenv("OCI_CLI_PROFILE", "ENV_PROFILE")
	t.Setenv("OCI_CLI_REGION", "us-ashburn-1")
	restore := mockOCIContext(t, map[string]string{
		"export -f json": `{"name":"example-context","profile":"CONTEXT_PROFILE","region":"us-phoenix-1","tenancy_ocid":"ocid1.tenancy.oc1..example","compartment_ocid":"ocid1.compartment.oc1..example"}`,
		"paths -o json":  `{"oci_config_path":"/tmp/oci-config"}`,
	})
	defer restore()

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := Run([]string{"get", "domains", "-o", "text"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("Run failed with %d: %s", code, stderr.String())
	}
	out := stdout.String()
	for _, want := range []string{"action: list", "context: example-context", "--compartment-id 'ocid1.compartment.oc1..example'", "--profile 'ENV_PROFILE'", "--region 'us-ashburn-1'"} {
		if !strings.Contains(out, want) {
			t.Fatalf("expected %q in output:\n%s", want, out)
		}
	}
}

func TestDescribeDomainRequiresID(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := Run([]string{"describe", "domain"}, &stdout, &stderr)
	if code == 0 || !strings.Contains(stderr.String(), "--domain-id is required") {
		t.Fatalf("expected missing domain id error, got %q", stderr.String())
	}
}

func TestGetServicesReadsOCIContext(t *testing.T) {
	restore := mockOCIContext(t, map[string]string{
		"auth service list -o json": `[{"name":"example-service","issuer":"https://example.identity.oraclecloud.com","scope":"https://service.example.com"}]`,
	})
	defer restore()
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := Run([]string{"get", "services", "-o", "text"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("Run failed with %d: %s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "example-service") || !strings.Contains(stdout.String(), "https://example.identity.oraclecloud.com") {
		t.Fatalf("unexpected services output: %s", stdout.String())
	}
}

func TestPlanAndApplyDomainCreatesAndWaitsForActive(t *testing.T) {
	var planOut bytes.Buffer
	var stderr bytes.Buffer
	code := Run([]string{
		"plan", "domain",
		"--name", "example-control-plane",
		"--description", "Example Control Plane identity domain",
		"--license-type", "free",
		"--home-region", "us-ashburn-1",
		"--compartment-id", "ocid1.tenancy.oc1..example",
		"--oci-context=false",
	}, &planOut, &stderr)
	if code != 0 {
		t.Fatalf("plan domain failed with %d: %s", code, stderr.String())
	}
	if !strings.Contains(planOut.String(), `"schemaVersion": "oci-idm.domain-plan.v1"`) {
		t.Fatalf("unexpected domain plan: %s", planOut.String())
	}

	dir := t.TempDir()
	planPath := filepath.Join(dir, "domain-plan.json")
	if err := os.WriteFile(planPath, planOut.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	restore := mockRunner(func(name string, args ...string) ([]byte, error) {
		joined := name + " " + strings.Join(args, " ")
		switch {
		case strings.Contains(joined, "iam domain list"):
			return []byte(`{"data":[]}`), nil
		case strings.Contains(joined, "iam domain create"):
			return []byte(`{"data":{"id":"ocid1.domain.oc1..created"}}`), nil
		case strings.Contains(joined, "iam domain get"):
			return []byte(`{"data":{"lifecycle-state":"ACTIVE"}}`), nil
		default:
			return nil, errors.New("unexpected command: " + joined)
		}
	})
	defer restore()

	var applyOut bytes.Buffer
	code = Run([]string{"apply", "domain", "-f", planPath, "--execute", "--confirm"}, &applyOut, &stderr)
	if code != 0 {
		t.Fatalf("apply domain failed with %d: %s", code, stderr.String())
	}
	for _, want := range []string{"created: domain", "id=ocid1.domain.oc1..created", "lifecycle=ACTIVE"} {
		if !strings.Contains(applyOut.String(), want) {
			t.Fatalf("expected %q in output:\n%s", want, applyOut.String())
		}
	}
}

func TestApplyDomainReusesMatchingDisplayName(t *testing.T) {
	plan := domainCreatePlan{
		SchemaVersion: domainPlanSchemaVersion, CompartmentOCID: "ocid1.tenancy.oc1..example",
		DisplayName: "example-control-plane", Description: "Example", HomeRegion: "us-ashburn-1",
		LicenseType: "free", MaxWaitSeconds: 1, WaitIntervalSeconds: 1,
	}
	dir := t.TempDir()
	planPath := filepath.Join(dir, "domain-plan.json")
	data, err := json.Marshal(plan)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(planPath, data, 0o600); err != nil {
		t.Fatal(err)
	}
	restore := mockRunner(func(name string, args ...string) ([]byte, error) {
		joined := name + " " + strings.Join(args, " ")
		switch {
		case strings.Contains(joined, "iam domain list"):
			return []byte(`{"data":[{"id":"ocid1.domain.oc1..existing","display-name":"example-control-plane"}]}`), nil
		case strings.Contains(joined, "iam domain get"):
			return []byte(`{"data":{"lifecycle-state":"ACTIVE"}}`), nil
		case strings.Contains(joined, "iam domain create"):
			return nil, errors.New("domain create should not run")
		default:
			return nil, errors.New("unexpected command: " + joined)
		}
	})
	defer restore()
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := Run([]string{"apply", "domain", "-f", planPath, "--execute", "--confirm"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("apply domain failed with %d: %s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "reused: domain id=ocid1.domain.oc1..existing lifecycle=ACTIVE") {
		t.Fatalf("unexpected apply output: %s", stdout.String())
	}
}

func TestPatchAppOfflineAccessPlansAndExecutesGuardedSCIMPatch(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	args := []string{
		"patch", "app",
		"--app-id", "resource-app-id",
		"--allow-offline",
		"--issuer", "https://idcs-example.identity.oraclecloud.com",
		"--profile", "OABCS1",
		"--region", "us-sanjose-1",
		"--oci-context=false",
		"--preflight=false",
	}
	code := Run(args, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("patch plan failed with %d: %s", code, stderr.String())
	}
	var plan appPatchPlan
	if err := json.Unmarshal(stdout.Bytes(), &plan); err != nil {
		t.Fatalf("decode patch plan: %v", err)
	}
	if plan.Executed || !plan.AllowOffline || plan.Command != "oci" {
		t.Fatalf("unexpected patch plan: %+v", plan)
	}
	if !strings.Contains(strings.Join(plan.Args, " "), "allowOffline") {
		t.Fatalf("patch args omit allowOffline: %v", plan.Args)
	}

	called := false
	restore := mockRunner(func(name string, commandArgs ...string) ([]byte, error) {
		joined := strings.Join(commandArgs, " ")
		if name != "oci" {
			t.Fatalf("unexpected command: %s %v", name, commandArgs)
		}
		if strings.Contains(joined, "identity-domains app patch") {
			called = true
			return []byte(`{"data":{"allow-offline":true}}`), nil
		}
		if strings.Contains(joined, "identity-domains app get") {
			return []byte(`{"data":{"id":"resource-app-id","allow-offline":true}}`), nil
		}
		t.Fatalf("unexpected OCI command: %v", commandArgs)
		return nil, nil
	})
	defer restore()
	stdout.Reset()
	stderr.Reset()
	code = Run(append(args, "--execute", "--confirm"), &stdout, &stderr)
	if code != 0 {
		t.Fatalf("patch execute failed with %d: %s", code, stderr.String())
	}
	if !called {
		t.Fatal("expected OCI patch command")
	}
}

func TestPatchAppOfflineAccessRejectsProtectedOracleServiceApp(t *testing.T) {
	restore := mockRunner(func(name string, commandArgs ...string) ([]byte, error) {
		if name != "oci" || !strings.Contains(strings.Join(commandArgs, " "), "identity-domains app get") {
			t.Fatalf("unexpected command: %s %v", name, commandArgs)
		}
		return []byte(`{
			"data": {
				"id": "resource-app-id",
				"name": "obpcs_APPID",
				"is-opc-service": true,
				"allow-offline": false,
				"service-type-urn": "AUTOBLOCKCHAIN",
				"editable-attributes": [{"name":"showInMyApps"}]
			}
		}`), nil
	})
	defer restore()

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := Run([]string{
		"patch", "app",
		"--app-id", "resource-app-id",
		"--allow-offline",
		"--issuer", "https://idcs-example.identity.oraclecloud.com",
		"--oci-context=false",
		"--execute",
		"--confirm",
	}, &stdout, &stderr)
	if code == 0 || !strings.Contains(stderr.String(), "protects allowOffline") || !strings.Contains(stderr.String(), "AUTOBLOCKCHAIN") {
		t.Fatalf("expected protected service app failure, code=%d stderr=%s", code, stderr.String())
	}
}

func TestPatchAppOfflineAccessReturnsNoopWhenAlreadyEnabled(t *testing.T) {
	restore := mockRunner(func(name string, commandArgs ...string) ([]byte, error) {
		if name != "oci" || !strings.Contains(strings.Join(commandArgs, " "), "identity-domains app get") {
			t.Fatalf("unexpected command: %s %v", name, commandArgs)
		}
		return []byte(`{"data":{"id":"resource-app-id","allow-offline":true}}`), nil
	})
	defer restore()

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := Run([]string{
		"patch", "app",
		"--app-id", "resource-app-id",
		"--allow-offline",
		"--issuer", "https://idcs-example.identity.oraclecloud.com",
		"--oci-context=false",
	}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("expected no-op success, code=%d stderr=%s", code, stderr.String())
	}
	var plan appPatchPlan
	if err := json.Unmarshal(stdout.Bytes(), &plan); err != nil {
		t.Fatal(err)
	}
	if plan.Status != "already-enabled" || plan.Executed || plan.CurrentAllowOffline == nil || !*plan.CurrentAllowOffline {
		t.Fatalf("unexpected no-op plan: %+v", plan)
	}
}

func TestPatchAppOfflineAccessRequiresConfirmation(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := Run([]string{
		"patch", "app",
		"--app-id", "resource-app-id",
		"--allow-offline",
		"--issuer", "https://idcs-example.identity.oraclecloud.com",
		"--oci-context=false",
		"--execute",
	}, &stdout, &stderr)
	if code == 0 || !strings.Contains(stderr.String(), "--execute requires --confirm") {
		t.Fatalf("expected confirmation failure, code=%d stderr=%s", code, stderr.String())
	}
}

func TestAssignAppRoleCreatesMissingGroupGrant(t *testing.T) {
	searches := 0
	created := false
	restore := mockRunner(func(name string, commandArgs ...string) ([]byte, error) {
		joined := strings.Join(commandArgs, " ")
		if name != "oci" {
			t.Fatalf("unexpected command: %s %v", name, commandArgs)
		}
		switch {
		case strings.Contains(joined, "identity-domains grants search"):
			searches++
			if searches == 1 {
				return []byte(`{"Resources":[]}`), nil
			}
			return []byte(`{"Resources":[{"id":"grant-id"}]}`), nil
		case strings.Contains(joined, "identity-domains grant create"):
			created = true
			for _, want := range []string{"ADMINISTRATOR_TO_GROUP", `"value":"web-app-id"`, `"attributeValue":"role-id"`, `"type":"Group"`, `"value":"group-id"`} {
				if !strings.Contains(joined, want) {
					t.Fatalf("grant create omits %q: %s", want, joined)
				}
			}
			return []byte(`{"id":"grant-id"}`), nil
		default:
			return nil, errors.New("unexpected command: " + joined)
		}
	})
	defer restore()
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := Run([]string{
		"assign", "app-role", "--app-id", "web-app-id", "--role-id", "role-id", "--group-id", "group-id",
		"--issuer", "https://idcs-example.identity.oraclecloud.com", "--oci-context=false", "--confirm",
	}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("assign failed with %d: %s", code, stderr.String())
	}
	var assignment appRoleAssignment
	if err := json.Unmarshal(stdout.Bytes(), &assignment); err != nil {
		t.Fatal(err)
	}
	if !created || searches != 2 || assignment.Status != "assigned" || !assignment.Executed || assignment.PrincipalType != "Group" {
		t.Fatalf("unexpected assignment: %+v", assignment)
	}
}

func TestAssignAppRoleResolvesCurrentUser(t *testing.T) {
	searches := 0
	created := false
	restore := mockRunner(func(name string, commandArgs ...string) ([]byte, error) {
		joined := strings.Join(commandArgs, " ")
		if name == "oci-context" {
			if joined != "auth subject --service obp --require-issuer https://idcs-example.identity.oraclecloud.com" {
				t.Fatalf("unexpected oci-context command: %s", joined)
			}
			return []byte(`{"issuer":"https://idcs-example.identity.oraclecloud.com","subject":"token-subject-id","not_expired":true}`), nil
		}
		if name != "oci" {
			t.Fatalf("unexpected command: %s %v", name, commandArgs)
		}
		switch {
		case strings.Contains(joined, "identity-domains users search"):
			if !strings.Contains(joined, `id eq "token-subject-id"`) {
				t.Fatalf("user search omits token subject: %s", joined)
			}
			return []byte(`{"Resources":[{"id":"resolved-user-id"}]}`), nil
		case strings.Contains(joined, "identity-domains grants search"):
			searches++
			if searches == 1 {
				return []byte(`{"Resources":[]}`), nil
			}
			return []byte(`{"Resources":[{"id":"grant-id"}]}`), nil
		case strings.Contains(joined, "identity-domains grant create"):
			created = true
			for _, want := range []string{"ADMINISTRATOR_TO_USER", `"type":"User"`, `"value":"resolved-user-id"`} {
				if !strings.Contains(joined, want) {
					t.Fatalf("grant create omits %q: %s", want, joined)
				}
			}
			return []byte(`{"id":"grant-id"}`), nil
		default:
			return nil, errors.New("unexpected command: " + joined)
		}
	})
	defer restore()
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := Run([]string{
		"assign", "app-role", "--app-id", "web-app-id", "--role-id", "role-id", "--current-user",
		"--issuer", "https://idcs-example.identity.oraclecloud.com", "--oci-context=false", "--confirm",
	}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("assign failed with %d: %s", code, stderr.String())
	}
	var assignment appRoleAssignment
	if err := json.Unmarshal(stdout.Bytes(), &assignment); err != nil {
		t.Fatal(err)
	}
	if !created || searches != 2 || assignment.PrincipalType != "User" || assignment.PrincipalID != "resolved-user-id" {
		t.Fatalf("unexpected assignment: %+v", assignment)
	}
}

func TestDiscoverUsesDefaultOBPTokenService(t *testing.T) {
	restore := mockOCIContext(t, map[string]string{
		"export -f json":            `{"name":"oabcs1","profile":"OABCS1","region":"us-sanjose-1"}`,
		"paths -o json":             `{"oci_config_path":"/tmp/oci-config"}`,
		"auth service list -o json": `[{"name":"obp","issuer":"https://idcs-example.identity.oraclecloud.com","scope":"https://example-oabcs.blockchain.ocp.oraclecloud.com:7443/restproxy"}]`,
	})
	defer restore()

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := Run([]string{
		"discover",
		"--query", "example",
		"--format", "text",
	}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("Run failed with %d: %s", code, stderr.String())
	}
	out := stdout.String()
	for _, want := range []string{"idcsEndpoint: https://idcs-example.identity.oraclecloud.com", "--profile 'OABCS1'", "--config-file '/tmp/oci-config'", "--region 'us-sanjose-1'"} {
		if !strings.Contains(out, want) {
			t.Fatalf("expected %q in output:\n%s", want, out)
		}
	}
}

func TestCloneAppAuthorizationCodeOutputsOCIContextTarget(t *testing.T) {
	restore := mockOCIContext(t, map[string]string{
		"export -f json":            `{"name":"oabcs1","profile":"OABCS1","region":"us-sanjose-1","current_service":"obp"}`,
		"paths -o json":             `{"oci_config_path":"/tmp/oci-config"}`,
		"auth service list -o json": `[{"name":"obp","issuer":"https://idcs-example.identity.oraclecloud.com","scope":"https://example-oabcs.blockchain.ocp.oraclecloud.com:7443/restproxy"}]`,
	})
	defer restore()

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := Run([]string{
		"clone", "app",
		"--flow", "authorization-code",
		"--name", "hebe-obp-user",
	}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("clone app failed with %d: %s", code, stderr.String())
	}
	var payload struct {
		CurrentService string `json:"currentService"`
		TokenServices  []struct {
			Name          string `json:"name"`
			Flow          string `json:"flow"`
			ClientID      string `json:"clientId"`
			Issuer        string `json:"issuer"`
			Scope         string `json:"scope"`
			RedirectURL   string `json:"redirectUrl"`
			OfflineAccess bool   `json:"offlineAccess"`
		} `json:"tokenServices"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &payload); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, stdout.String())
	}
	if payload.CurrentService != "hebe-obp-user" {
		t.Fatalf("unexpected current service: %+v", payload)
	}
	if len(payload.TokenServices) != 1 {
		t.Fatalf("expected one token service: %+v", payload)
	}
	service := payload.TokenServices[0]
	if service.Name != "hebe-obp-user" || service.ClientID != "hebe-obp-user" || service.Flow != "authorization-code" {
		t.Fatalf("unexpected token service: %+v", service)
	}
	if service.Issuer == "" || service.Scope == "" || service.RedirectURL != "http://127.0.0.1:8180/callback" {
		t.Fatalf("missing inherited target values: %+v", service)
	}
	if !service.OfflineAccess {
		t.Fatalf("authorization-code handoff must request offline access: %+v", service)
	}
}

func TestDiagnoseText(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := Run([]string{
		"diagnose",
		"--service", "obp",
		"--issuer", "https://idcs-example.identity.oraclecloud.com",
		"--resource-app-id", "resource-app-id",
		"--candidate-app-id", "candidate-app-id",
		"--known-good-app-id", "known-good-app-id",
		"--profile", "DEFAULT",
		"--format", "text",
	}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("Run failed with %d: %s", code, stderr.String())
	}
	out := stdout.String()
	for _, want := range []string{
		"get-resource-app",
		"search-grants-for-candidate",
		"search-grants-for-known-good",
		"search-account-mgmt-for-resource-app",
		"search-same-name-user-for-candidate",
		"search-grants-for-candidate-user",
		"--profile 'DEFAULT'",
		"OBP_ADMIN_FORBIDDEN",
		"allowOffline,refreshTokenExpiry,isOPCService,editableAttributes",
		"client that allows refresh_token is not sufficient",
		"short-lived user access tokens, JWT assertions, or client credentials",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("expected %q in output:\n%s", want, out)
		}
	}
}

func TestDiagnoseUsesOCIContextProfile(t *testing.T) {
	restore := mockOCIContext(t, map[string]string{
		"export -f json":            `{"name":"oabcs1","profile":"OABCS1","region":"us-sanjose-1"}`,
		"paths -o json":             `{"oci_config_path":"/tmp/oci-config"}`,
		"auth service list -o json": `[{"name":"obp","issuer":"https://idcs-example.identity.oraclecloud.com","scope":"https://example-oabcs.blockchain.ocp.oraclecloud.com:7443/restproxy"}]`,
	})
	defer restore()

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := Run([]string{
		"diagnose",
		"--service", "obp",
		"--resource-app-id", "resource-app-id",
		"--candidate-app-id", "candidate-app-id",
		"--format", "text",
	}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("Run failed with %d: %s", code, stderr.String())
	}
	out := stdout.String()
	for _, want := range []string{"--profile 'OABCS1'", "--config-file '/tmp/oci-config'", "--region 'us-sanjose-1'"} {
		if !strings.Contains(out, want) {
			t.Fatalf("expected %q in output:\n%s", want, out)
		}
	}
}

func TestDoctorWithPlan(t *testing.T) {
	restore := mockOCIContext(t, map[string]string{
		"export -f json":            `{"name":"oabcs1","profile":"OABCS1","region":"us-sanjose-1"}`,
		"paths -o json":             `{"oci_config_path":"/tmp/oci-config"}`,
		"auth service list -o json": `[{"name":"obp","issuer":"https://idcs-example.identity.oraclecloud.com","scope":"https://example-oabcs.blockchain.ocp.oraclecloud.com:7443/restproxy"}]`,
	})
	defer restore()

	dir := t.TempDir()
	planPath := filepath.Join(dir, "plan.json")
	var planOut bytes.Buffer
	var stderr bytes.Buffer
	code := Run([]string{
		"plan",
		"--service", "obp",
		"--issuer", "https://idcs-example.identity.oraclecloud.com",
		"--platform", "https://example-oabcs.blockchain.ocp.oraclecloud.com:7443/restproxy",
		"--include", "user",
	}, &planOut, &stderr)
	if code != 0 {
		t.Fatalf("plan failed with %d: %s", code, stderr.String())
	}
	if err := os.WriteFile(planPath, planOut.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}

	var doctorOut bytes.Buffer
	code = Run([]string{"doctor", "plan", "-f", planPath, "-o", "text"}, &doctorOut, &stderr)
	if code != 0 {
		t.Fatalf("doctor failed with %d: %s", code, stderr.String())
	}
	out := doctorOut.String()
	for _, want := range []string{"pass: oci-context-current", "pass: issuer", "pass: oci-context-handoff"} {
		if !strings.Contains(out, want) {
			t.Fatalf("expected %q in output:\n%s", want, out)
		}
	}
}

func TestMaterializeAndValidate(t *testing.T) {
	dir := t.TempDir()
	planPath := filepath.Join(dir, "plan.json")
	var planOut bytes.Buffer
	var stderr bytes.Buffer
	code := Run([]string{
		"plan",
		"--service", "obp",
		"--issuer", "https://idcs-example.identity.oraclecloud.com",
		"--platform", "https://example-oabcs.blockchain.ocp.oraclecloud.com:7443/restproxy",
		"--resource-app-id", "resource-app-id",
		"--base-app-name", "example-obp_APPID",
		"--include", "jwt-service",
		"--role-preset", "obp-admin",
	}, &planOut, &stderr)
	if code != 0 {
		t.Fatalf("plan failed with %d: %s", code, stderr.String())
	}
	if err := os.WriteFile(planPath, planOut.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}

	var materializeOut bytes.Buffer
	outDir := filepath.Join(dir, "artifacts")
	code = Run([]string{
		"materialize", "plan",
		"-f", planPath,
		"--out", outDir,
	}, &materializeOut, &stderr)
	if code != 0 {
		t.Fatalf("materialize failed with %d: %s", code, stderr.String())
	}
	for _, name := range []string{
		"plan.json",
		"example-obp-service-jwt.json",
		"example-obp-service-jwt-oauth-client-certificate.json",
		"example-obp-service-jwt-grant-admin.json",
		"example-obp-service-jwt-principal-user.json",
		"example-obp-service-jwt-principal-user-grant-admin.json",
		"apply.sh",
		"validate.sh",
		"cleanup.sh",
		"oci-context.handoff.json",
		"oci-context-token-services.yml",
		"oci-context-token-commands.sh",
	} {
		if _, err := os.Stat(filepath.Join(outDir, name)); err != nil {
			t.Fatalf("expected %s: %v", name, err)
		}
	}

	var validateOut bytes.Buffer
	code = Run([]string{
		"validate", "plan",
		"-f", planPath,
		"--format", "text",
	}, &validateOut, &stderr)
	if code != 0 {
		t.Fatalf("validate failed with %d: %s", code, stderr.String())
	}
	if !strings.Contains(validateOut.String(), "placeholder <ADMIN-app-role-id>") {
		t.Fatalf("expected placeholder warning in validate output:\n%s", validateOut.String())
	}

	var applyOut bytes.Buffer
	applyDir := filepath.Join(dir, "apply-artifacts")
	code = Run([]string{
		"apply", "plan",
		"-f", planPath,
		"--out", applyDir,
	}, &applyOut, &stderr)
	if code == 0 || !strings.Contains(stderr.String(), "--confirm is required") {
		t.Fatalf("apply without confirmation did not fail closed: %s", stderr.String())
	}
	stderr.Reset()
	code = Run([]string{
		"apply", "plan",
		"-f", planPath,
		"--out", applyDir,
		"--execute",
	}, &applyOut, &stderr)
	if code == 0 || !strings.Contains(stderr.String(), "--confirm is required") {
		t.Fatalf("compatibility --execute did not retain the confirmation gate: %s", stderr.String())
	}
}

func TestApplyCreatesApp(t *testing.T) {
	restore := mockRunner(func(name string, args ...string) ([]byte, error) {
		joined := name + " " + strings.Join(args, " ")
		switch {
		case strings.Contains(joined, "identity-domains apps search"):
			return []byte(`{"Resources":[]}`), nil
		case strings.Contains(joined, "identity-domains app create"):
			return []byte(`{"data":{"id":"created-app-id"}}`), nil
		default:
			return nil, errors.New("unexpected command: " + joined)
		}
	})
	defer restore()

	dir := t.TempDir()
	planPath := filepath.Join(dir, "plan.json")
	var planOut bytes.Buffer
	var stderr bytes.Buffer
	code := Run([]string{
		"plan",
		"--issuer", "https://idcs-example.identity.oraclecloud.com",
		"--scope", "https://service.example.com/.default",
		"--include", "user",
	}, &planOut, &stderr)
	if code != 0 {
		t.Fatalf("plan failed with %d: %s", code, stderr.String())
	}
	if err := os.WriteFile(planPath, planOut.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}

	var applyOut bytes.Buffer
	code = Run([]string{"apply", "plan", "-f", planPath, "--out", filepath.Join(dir, "apply"), "--confirm", "-o", "text"}, &applyOut, &stderr)
	if code != 0 {
		t.Fatalf("apply failed with %d: %s", code, stderr.String())
	}
	if !strings.Contains(applyOut.String(), "created: app-") || !strings.Contains(applyOut.String(), "id=created-app-id") {
		t.Fatalf("unexpected apply output:\n%s", applyOut.String())
	}
}

func TestPlanOutputsOCIContextYAML(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := Run([]string{
		"plan",
		"--service", "obp",
		"--issuer", "https://idcs-example.identity.oraclecloud.com",
		"--platform", "https://example-oabcs.blockchain.ocp.oraclecloud.com:7443/restproxy",
		"--resource-app-id", "resource-app-id",
		"--include", "user,jwt-service",
		"-o", "oci-context-yaml",
	}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("plan oci-context-yaml failed with %d: %s", code, stderr.String())
	}
	out := stdout.String()
	for _, want := range []string{
		"token_services:",
		"name: 'obp'",
		"flow: 'authorization-code'",
		"name: 'obp-jwt-service'",
		"flow: 'jwt-client-credentials'",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("expected %q in plan output:\n%s", want, out)
		}
	}
}

func TestPlanOutputsOChainDotenv(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := Run([]string{
		"plan",
		"--service", "obp",
		"--issuer", "https://idcs-example.identity.oraclecloud.com",
		"--platform", "https://example-oabcs.blockchain.ocp.oraclecloud.com:7443/restproxy",
		"--include", "user,jwt-service",
		"-o", "ochain-dotenv",
	}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("plan ochain-dotenv failed with %d: %s", code, stderr.String())
	}
	want := "OCHAIN_TOKEN_COMMAND=\"oci-context auth token --service 'obp-jwt-service' --no-login --format raw\"\n"
	if stdout.String() != want {
		t.Fatalf("unexpected OChain dotenv: got %q want %q", stdout.String(), want)
	}
}

func TestPlanAppsOutputsOChainDotenv(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := Run([]string{
		"plan", "apps",
		"--service", "obp",
		"--issuer", "https://idcs-example.identity.oraclecloud.com",
		"--platform", "https://example-oabcs.blockchain.ocp.oraclecloud.com:7443/restproxy",
		"--include", "user,jwt-service",
		"-o", "ochain-dotenv",
	}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("plan apps ochain-dotenv failed with %d: %s", code, stderr.String())
	}
	want := "OCHAIN_TOKEN_COMMAND=\"oci-context auth token --service 'obp-jwt-service' --no-login --format raw\"\n"
	if stdout.String() != want {
		t.Fatalf("unexpected OChain dotenv: got %q want %q", stdout.String(), want)
	}
}

func TestHandoffOCIContextYAML(t *testing.T) {
	dir := t.TempDir()
	planPath := filepath.Join(dir, "plan.json")
	var planOut bytes.Buffer
	var stderr bytes.Buffer
	code := Run([]string{
		"plan",
		"--service", "obp",
		"--issuer", "https://idcs-example.identity.oraclecloud.com",
		"--platform", "https://example-oabcs.blockchain.ocp.oraclecloud.com:7443/restproxy",
		"--resource-app-id", "resource-app-id",
		"--base-app-name", "example-obp_APPID",
		"--include", "user,jwt-service",
		"--app-role-grants", "ADMIN=admin-role-id",
	}, &planOut, &stderr)
	if code != 0 {
		t.Fatalf("plan failed with %d: %s", code, stderr.String())
	}
	if err := os.WriteFile(planPath, planOut.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}

	var handoffOut bytes.Buffer
	code = Run([]string{
		"handoff",
		"-f", planPath,
		"--target", "oci-context",
		"--format", "yaml",
	}, &handoffOut, &stderr)
	if code != 0 {
		t.Fatalf("handoff failed with %d: %s", code, stderr.String())
	}
	out := handoffOut.String()
	for _, want := range []string{
		"token_services:",
		"name: 'obp'",
		"flow: 'authorization-code'",
		"name: 'obp-jwt-service'",
		"flow: 'jwt-client-credentials'",
		"jwt_audience: 'https://identity.oraclecloud.com/'",
		"private_key_file_env:",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("expected %q in handoff output:\n%s", want, out)
		}
	}

	var commandsOut bytes.Buffer
	code = Run([]string{
		"handoff",
		"-f", planPath,
		"--target", "oci-context",
		"--format", "commands",
	}, &commandsOut, &stderr)
	if code != 0 {
		t.Fatalf("handoff commands failed with %d: %s", code, stderr.String())
	}
	commands := commandsOut.String()
	if strings.Contains(commands, "--flow 'authorization-code' --issuer") &&
		strings.Contains(strings.Split(commands, "--flow 'authorization-code'")[1], "--no-login") &&
		strings.Index(commands, "--no-login") < strings.Index(commands, "--flow 'jwt-client-credentials'") {
		t.Fatalf("authorization-code command should not include --no-login:\n%s", commands)
	}
	if !strings.Contains(commands, "--flow 'jwt-client-credentials'") || !strings.Contains(commands, "--no-login") {
		t.Fatalf("jwt-client-credentials command should include --no-login:\n%s", commands)
	}
}

func TestHandoffReadsPlanFromStdin(t *testing.T) {
	dir := t.TempDir()
	planPath := filepath.Join(dir, "plan.json")
	var planOut bytes.Buffer
	var stderr bytes.Buffer
	code := Run([]string{
		"plan",
		"--service", "obp",
		"--issuer", "https://idcs-example.identity.oraclecloud.com",
		"--platform", "https://example-oabcs.blockchain.ocp.oraclecloud.com:7443/restproxy",
		"--include", "user",
	}, &planOut, &stderr)
	if code != 0 {
		t.Fatalf("plan failed with %d: %s", code, stderr.String())
	}
	if err := os.WriteFile(planPath, planOut.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}

	previous := stdinReader
	stdinReader = bytes.NewReader(planOut.Bytes())
	defer func() { stdinReader = previous }()

	var handoffOut bytes.Buffer
	code = Run([]string{"handoff", "-f", "-", "-o", "yaml"}, &handoffOut, &stderr)
	if code != 0 {
		t.Fatalf("handoff stdin failed with %d: %s", code, stderr.String())
	}
	if !strings.Contains(handoffOut.String(), "token_services:") || !strings.Contains(handoffOut.String(), "name: 'obp'") {
		t.Fatalf("unexpected handoff output:\n%s", handoffOut.String())
	}
}

func TestHandoffOChainEnv(t *testing.T) {
	dir := t.TempDir()
	planPath := filepath.Join(dir, "plan.json")
	var planOut bytes.Buffer
	var stderr bytes.Buffer
	code := Run([]string{
		"plan",
		"--service", "obp",
		"--issuer", "https://idcs-example.identity.oraclecloud.com",
		"--platform", "https://example-oabcs.blockchain.ocp.oraclecloud.com:7443/restproxy",
		"--include", "user,jwt-service",
	}, &planOut, &stderr)
	if code != 0 {
		t.Fatalf("plan failed with %d: %s", code, stderr.String())
	}
	if err := os.WriteFile(planPath, planOut.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}

	var handoffOut bytes.Buffer
	code = Run([]string{"handoff", "-f", planPath, "--target", "ochain", "-o", "env"}, &handoffOut, &stderr)
	if code != 0 {
		t.Fatalf("handoff target ochain env failed with %d: %s", code, stderr.String())
	}
	out := handoffOut.String()
	if !strings.Contains(out, "export OCHAIN_TOKEN_COMMAND=") || !strings.Contains(out, "obp-jwt-service") || !strings.Contains(out, "--no-login --format raw") {
		t.Fatalf("unexpected OChain handoff:\n%s", out)
	}
}

func TestHandoffOChainDotenv(t *testing.T) {
	dir := t.TempDir()
	planPath := filepath.Join(dir, "plan.json")
	var planOut bytes.Buffer
	var stderr bytes.Buffer
	code := Run([]string{
		"plan",
		"--service", "obp",
		"--issuer", "https://idcs-example.identity.oraclecloud.com",
		"--platform", "https://example-oabcs.blockchain.ocp.oraclecloud.com:7443/restproxy",
		"--include", "user,jwt-service",
	}, &planOut, &stderr)
	if code != 0 {
		t.Fatalf("plan failed with %d: %s", code, stderr.String())
	}
	if err := os.WriteFile(planPath, planOut.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}

	var handoffOut bytes.Buffer
	code = Run([]string{"handoff", "-f", planPath, "--target", "ochain", "--output", "dotenv"}, &handoffOut, &stderr)
	if code != 0 {
		t.Fatalf("handoff target ochain dotenv failed with %d: %s", code, stderr.String())
	}
	want := "OCHAIN_TOKEN_COMMAND=\"oci-context auth token --service 'obp-jwt-service' --no-login --format raw\"\n"
	if handoffOut.String() != want {
		t.Fatalf("unexpected OChain dotenv: got %q want %q", handoffOut.String(), want)
	}
}

func TestHandoffOChainLegacyFormat(t *testing.T) {
	dir := t.TempDir()
	planPath := filepath.Join(dir, "plan.json")
	var planOut bytes.Buffer
	var stderr bytes.Buffer
	code := Run([]string{
		"plan",
		"--service", "obp",
		"--issuer", "https://idcs-example.identity.oraclecloud.com",
		"--platform", "https://example-oabcs.blockchain.ocp.oraclecloud.com:7443/restproxy",
		"--include", "user,jwt-service",
	}, &planOut, &stderr)
	if code != 0 {
		t.Fatalf("plan failed with %d: %s", code, stderr.String())
	}
	if err := os.WriteFile(planPath, planOut.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}

	var handoffOut bytes.Buffer
	code = Run([]string{"handoff", "--plan", planPath, "--format", "ochain-env"}, &handoffOut, &stderr)
	if code != 0 {
		t.Fatalf("legacy ochain-env failed with %d: %s", code, stderr.String())
	}
	if !strings.Contains(handoffOut.String(), "export OCHAIN_TOKEN_COMMAND=") {
		t.Fatalf("unexpected legacy OChain output:\n%s", handoffOut.String())
	}
}

func TestHandoffImport(t *testing.T) {
	restore := mockOCIContext(t, map[string]string{
		"auth service import --file " + filepath.Join("ARTIFACTS", "oci-context-token-services.yml") + " --dry-run": "import ok\n",
	})
	defer restore()

	dir := t.TempDir()
	planPath := filepath.Join(dir, "plan.json")
	outDir := filepath.Join(dir, "ARTIFACTS")
	var planOut bytes.Buffer
	var stderr bytes.Buffer
	code := Run([]string{
		"plan",
		"--service", "obp",
		"--issuer", "https://idcs-example.identity.oraclecloud.com",
		"--platform", "https://example-oabcs.blockchain.ocp.oraclecloud.com:7443/restproxy",
		"--include", "user",
	}, &planOut, &stderr)
	if code != 0 {
		t.Fatalf("plan failed with %d: %s", code, stderr.String())
	}
	if err := os.WriteFile(planPath, planOut.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}

	expectedKey := "auth service import --file " + filepath.Join(outDir, "oci-context-token-services.yml") + " --dry-run"
	restore()
	restore = mockOCIContext(t, map[string]string{expectedKey: "import ok\n"})
	defer restore()

	var handoffOut bytes.Buffer
	code = Run([]string{"handoff", "-f", planPath, "--import", "--dry-run", "--out", outDir}, &handoffOut, &stderr)
	if code != 0 {
		t.Fatalf("handoff import failed with %d: %s", code, stderr.String())
	}
	if handoffOut.String() != "import ok\n" {
		t.Fatalf("unexpected import output: %q", handoffOut.String())
	}
}

func mockOCIContext(t *testing.T, responses map[string]string) func() {
	t.Helper()
	previous := runCommand
	runCommand = func(name string, args ...string) ([]byte, error) {
		if name != "oci-context" {
			return nil, errors.New("unexpected command: " + name)
		}
		key := strings.Join(args, " ")
		if response, ok := responses[key]; ok {
			return []byte(response), nil
		}
		return nil, errors.New("unexpected args: " + key)
	}
	return func() {
		runCommand = previous
	}
}

func mockRunner(runner commandRunner) func() {
	previous := runCommand
	runCommand = runner
	return func() {
		runCommand = previous
	}
}
