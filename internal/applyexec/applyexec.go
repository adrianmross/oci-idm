package applyexec

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/adrianmross/oci-idm/internal/planner"
)

type Runner func(name string, args ...string) ([]byte, error)

type Result struct {
	SchemaVersion string `json:"schemaVersion"`
	OutDir        string `json:"outDir"`
	Steps         []Step `json:"steps"`
}

type Step struct {
	Key     string `json:"key"`
	Name    string `json:"name,omitempty"`
	Status  string `json:"status"`
	ID      string `json:"id,omitempty"`
	Command string `json:"command,omitempty"`
	Message string `json:"message,omitempty"`
}

const SchemaVersion = "oci-idm.apply.v1"

func Execute(plan planner.Plan, outDir string, runner Runner) (Result, error) {
	if runner == nil {
		return Result{}, fmt.Errorf("runner is required")
	}
	if strings.TrimSpace(outDir) == "" {
		outDir = "oci-idm-apply"
	}
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return Result{}, err
	}
	result := Result{SchemaVersion: SchemaVersion, OutDir: outDir}

	appIDs := map[string]string{}
	userIDs := map[string]string{}
	for _, app := range plan.Apps {
		for _, action := range app.OCIPreCreate {
			if hasPlaceholder(action.Payload) {
				return result, fmt.Errorf("%s contains placeholders; materialize, fill %s, then rerun apply --confirm", action.Key, action.PayloadFile)
			}
			id, step, err := createFromPayload(plan.Target, outDir, action.PayloadFile, "o-auth-client-certificate", action.Payload, runner)
			step.Key = action.Key
			step.Name = action.PayloadFile
			result.Steps = append(result.Steps, step)
			if err != nil {
				return result, err
			}
			_ = id
		}

		appID, step, err := ensureApp(plan.Target, outDir, app, runner)
		result.Steps = append(result.Steps, step)
		if err != nil {
			return result, err
		}
		appIDs[app.Name] = appID

		if app.Principal != nil {
			userID, step, err := ensureUser(plan.Target, outDir, app, runner)
			result.Steps = append(result.Steps, step)
			if err != nil {
				return result, err
			}
			userIDs[app.Name] = userID
		}

		for _, action := range app.OCIPostCreate {
			step, err := ensureGrant(plan.Target, outDir, app, action, appIDs[app.Name], userIDs[app.Name], runner)
			result.Steps = append(result.Steps, step)
			if err != nil {
				return result, err
			}
		}
	}
	return result, nil
}

func ensureApp(target planner.Target, outDir string, app planner.AppPlan, runner Runner) (string, Step, error) {
	id, command, err := searchFirstID(target, "apps", "name eq \""+app.Name+"\"", runner)
	if err != nil {
		return "", Step{Key: "app-" + app.Name, Name: app.Name, Status: "error", Command: command, Message: err.Error()}, err
	}
	if id != "" {
		return id, Step{Key: "app-" + app.Name, Name: app.Name, Status: "reused", ID: id, Command: command}, nil
	}
	if hasPlaceholder(app.OCICreatePayload) {
		return "", Step{Key: "app-" + app.Name, Name: app.Name, Status: "blocked"}, fmt.Errorf("%s contains placeholders", app.OCICreatePayloadFile)
	}
	id, step, err := createFromPayload(target, outDir, app.OCICreatePayloadFile, "app", app.OCICreatePayload, runner)
	step.Key = "app-" + app.Name
	step.Name = app.Name
	return id, step, err
}

func ensureUser(target planner.Target, outDir string, app planner.AppPlan, runner Runner) (string, Step, error) {
	principal := app.Principal
	if principal == nil {
		return "", Step{}, nil
	}
	id, command, err := searchFirstID(target, "users", "userName eq \""+principal.UserName+"\"", runner)
	if err != nil {
		return "", Step{Key: "principal-user-" + app.Name, Name: principal.UserName, Status: "error", Command: command, Message: err.Error()}, err
	}
	if id != "" {
		return id, Step{Key: "principal-user-" + app.Name, Name: principal.UserName, Status: "reused", ID: id, Command: command}, nil
	}
	if hasPlaceholder(principal.CreatePayload) {
		return "", Step{Key: "principal-user-" + app.Name, Name: principal.UserName, Status: "blocked"}, fmt.Errorf("%s contains placeholders", principal.PayloadFile)
	}
	id, step, err := createFromPayload(target, outDir, principal.PayloadFile, "user", principal.CreatePayload, runner)
	step.Key = "principal-user-" + app.Name
	step.Name = principal.UserName
	return id, step, err
}

func ensureGrant(target planner.Target, outDir string, app planner.AppPlan, action planner.OCIAction, appID string, userID string, runner Runner) (Step, error) {
	payload := normalizePayload(action.Payload)
	roleID := nestedString(payload, "entitlement", "attributeValue")
	if strings.HasPrefix(roleID, "<") || roleID == "" {
		return Step{Key: action.Key + "-" + app.Name, Status: "blocked", Name: action.PayloadFile}, fmt.Errorf("%s has unresolved app-role entitlement %q", action.PayloadFile, roleID)
	}
	granteeID := appID
	granteeType := "App"
	if action.Key == "grant-principal-user-app-role" {
		granteeID = userID
		granteeType = "User"
	}
	if strings.TrimSpace(granteeID) == "" {
		return Step{Key: action.Key + "-" + app.Name, Status: "blocked", Name: action.PayloadFile}, fmt.Errorf("%s cannot resolve %s grantee id", action.PayloadFile, granteeType)
	}

	id, command, err := searchGrantID(target, granteeID, roleID, runner)
	if err != nil {
		return Step{Key: action.Key + "-" + app.Name, Status: "error", Name: action.PayloadFile, Command: command, Message: err.Error()}, err
	}
	if id != "" {
		return Step{Key: action.Key + "-" + app.Name, Status: "reused", Name: action.PayloadFile, ID: id, Command: command}, nil
	}

	setNested(payload, granteeID, "grantee", "value")
	setNested(payload, granteeType, "grantee", "type")
	setNested(payload, adminResourceBase(target.IDCSEndpoint)+"/"+granteeType+"s/"+granteeID, "grantee", "$ref")
	if hasPlaceholder(payload) {
		return Step{Key: action.Key + "-" + app.Name, Status: "blocked", Name: action.PayloadFile}, fmt.Errorf("%s contains placeholders", action.PayloadFile)
	}
	_, step, err := createFromPayload(target, outDir, action.PayloadFile, "grant", payload, runner)
	step.Key = action.Key + "-" + app.Name
	step.Name = action.PayloadFile
	return step, err
}

func createFromPayload(target planner.Target, outDir string, payloadFile string, resource string, payload any, runner Runner) (string, Step, error) {
	path := filepath.Join(outDir, payloadFile)
	data, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return "", Step{Status: "error", Message: err.Error()}, err
	}
	data = append(data, '\n')
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return "", Step{Status: "error", Message: err.Error()}, err
	}
	args := identityArgs(target, resource, "create", "--from-json", "file://"+path)
	out, err := runner("oci", args...)
	command := commandString("oci", args...)
	if err != nil {
		return "", Step{Status: "error", Command: command, Message: err.Error()}, err
	}
	id := firstID(out)
	return id, Step{Status: "created", ID: id, Command: command}, nil
}

func searchFirstID(target planner.Target, resource string, filter string, runner Runner) (string, string, error) {
	args := identityArgs(target, resource, "search",
		"--schemas", `["urn:ietf:params:scim:api:messages:2.0:SearchRequest"]`,
		"--filter", filter,
		"--attributes", `["id","name","userName"]`,
		"--count", "1",
	)
	out, err := runner("oci", args...)
	command := commandString("oci", args...)
	if err != nil {
		return "", command, err
	}
	return firstID(out), command, nil
}

func searchGrantID(target planner.Target, granteeID string, roleID string, runner Runner) (string, string, error) {
	args := identityArgs(target, "grants", "search",
		"--schemas", `["urn:ietf:params:scim:api:messages:2.0:SearchRequest"]`,
		"--filter", "grantee.value eq \""+granteeID+"\"",
		"--attributes", `["id","entitlement","grantee","grantMechanism"]`,
		"--count", "100",
	)
	out, err := runner("oci", args...)
	command := commandString("oci", args...)
	if err != nil {
		return "", command, err
	}
	return firstGrantIDForRole(out, roleID), command, nil
}

func identityArgs(target planner.Target, resource string, action string, args ...string) []string {
	parts := []string{"identity-domains", resource, action, "--endpoint", target.IDCSEndpoint}
	if target.OCIProfile != "" {
		parts = append(parts, "--profile", target.OCIProfile)
	}
	if target.OCIConfigPath != "" {
		parts = append(parts, "--config-file", target.OCIConfigPath)
	}
	if target.OCIRegion != "" {
		parts = append(parts, "--region", target.OCIRegion)
	}
	return append(parts, args...)
}

func firstID(data []byte) string {
	var value any
	if json.Unmarshal(data, &value) != nil {
		return ""
	}
	return firstIDValue(value)
}

func firstIDValue(value any) string {
	switch v := value.(type) {
	case map[string]any:
		for _, key := range []string{"Resources", "resources", "data"} {
			if id := firstIDValue(v[key]); id != "" {
				return id
			}
		}
		if id, ok := v["id"].(string); ok {
			return id
		}
	case []any:
		for _, item := range v {
			if id := firstIDValue(item); id != "" {
				return id
			}
		}
	}
	return ""
}

func firstGrantIDForRole(data []byte, roleID string) string {
	var value any
	if json.Unmarshal(data, &value) != nil {
		return ""
	}
	for _, item := range resourceItems(value) {
		if nestedString(item, "entitlement", "attributeValue") == roleID {
			if id, ok := item["id"].(string); ok {
				return id
			}
		}
	}
	return ""
}

func resourceItems(value any) []map[string]any {
	switch v := value.(type) {
	case map[string]any:
		for _, key := range []string{"Resources", "resources", "data"} {
			if items := resourceItems(v[key]); len(items) > 0 {
				return items
			}
		}
		return []map[string]any{v}
	case []any:
		items := []map[string]any{}
		for _, item := range v {
			if m, ok := item.(map[string]any); ok {
				items = append(items, m)
			}
		}
		return items
	default:
		return nil
	}
}

func normalizePayload(value any) map[string]any {
	data, _ := json.Marshal(value)
	var payload map[string]any
	_ = json.Unmarshal(data, &payload)
	return payload
}

func hasPlaceholder(value any) bool {
	data, _ := json.Marshal(value)
	return strings.Contains(string(data), "<")
}

func nestedString(value map[string]any, keys ...string) string {
	var current any = value
	for _, key := range keys {
		m, ok := current.(map[string]any)
		if !ok {
			return ""
		}
		current = m[key]
	}
	s, _ := current.(string)
	return s
}

func setNested(value map[string]any, newValue string, keys ...string) {
	if len(keys) == 0 {
		return
	}
	current := value
	for _, key := range keys[:len(keys)-1] {
		next, ok := current[key].(map[string]any)
		if !ok {
			next = map[string]any{}
			current[key] = next
		}
		current = next
	}
	current[keys[len(keys)-1]] = newValue
}

func adminResourceBase(endpoint string) string {
	endpoint = strings.TrimRight(endpoint, "/")
	if !strings.Contains(strings.TrimPrefix(endpoint, "https://"), ":") {
		endpoint += ":443"
	}
	return endpoint + "/admin/v1"
}

func commandString(name string, args ...string) string {
	parts := append([]string{name}, args...)
	for i, part := range parts {
		if strings.ContainsAny(part, " \t\n\"'") {
			parts[i] = "'" + strings.ReplaceAll(part, "'", "'\"'\"'") + "'"
		}
	}
	return strings.Join(parts, " ")
}
