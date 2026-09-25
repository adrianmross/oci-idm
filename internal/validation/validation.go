package validation

import (
	"encoding/json"
	"io"
	"os"
	"strings"

	"github.com/adrianmross/oci-idm/internal/planner"
)

const SchemaVersion = "oci-idm.validation.v1"

type Report struct {
	SchemaVersion string  `json:"schemaVersion"`
	Checks        []Check `json:"checks"`
	Commands      []Check `json:"commands"`
}

type Check struct {
	Key      string `json:"key"`
	Status   string `json:"status"`
	Message  string `json:"message"`
	Command  string `json:"command,omitempty"`
	Severity string `json:"severity,omitempty"`
}

func FromPlanFile(path string) (Report, error) {
	data, err := readPlanBytes(path)
	if err != nil {
		return Report{}, err
	}
	var plan planner.Plan
	if err := json.Unmarshal(data, &plan); err != nil {
		return Report{}, err
	}
	if err := plan.ValidateContract(); err != nil {
		return Report{}, err
	}
	return FromPlan(plan), nil
}

func readPlanBytes(path string) ([]byte, error) {
	if strings.TrimSpace(path) == "-" {
		return io.ReadAll(os.Stdin)
	}
	return os.ReadFile(path)
}

func FromPlan(plan planner.Plan) Report {
	report := Report{SchemaVersion: SchemaVersion}
	add := func(key, status, severity, message string) {
		report.Checks = append(report.Checks, Check{Key: key, Status: status, Severity: severity, Message: message})
	}
	if plan.Target.Issuer == "" {
		add("issuer", "fail", "error", "issuer is required")
	} else {
		add("issuer", "pass", "", "issuer is set")
	}
	if plan.Target.Scope == "" {
		add("scope", "fail", "error", "scope is required")
	} else {
		add("scope", "pass", "", "scope is set")
	}
	if plan.Target.ResourceAppID == "" {
		add("resource-app-id", "warn", "warning", "resource app id is not set; role grant payloads cannot be generated")
	} else {
		add("resource-app-id", "pass", "", "resource app id is set")
	}
	for _, app := range plan.Apps {
		for _, action := range app.OCIPostCreate {
			value, ok := grantEntitlementValue(action.Payload)
			if !ok {
				continue
			}
			if strings.HasPrefix(value, "<") {
				add("app-role-"+app.Name, "warn", "warning", "app role grant "+action.Description+" still uses placeholder "+value)
			}
		}
		if app.Key == planner.AppJWTService && len(app.OCIPreCreate) == 0 {
			add("jwt-certificate-"+app.Name, "warn", "warning", "jwt-service app has no OAuth client certificate registration action")
		}
		if app.Principal != nil && app.Principal.UserName != app.Name {
			add("principal-"+app.Name, "warn", "warning", "principal user name should match OAuth client id for same-name-user mode")
		}
	}
	report.Commands = validationCommands(plan)
	return report
}

func grantEntitlementValue(payload any) (string, bool) {
	switch value := payload.(type) {
	case planner.GrantInput:
		return value.Entitlement.AttributeValue, value.Entitlement.AttributeValue != ""
	case map[string]any:
		entitlement, ok := value["entitlement"].(map[string]any)
		if !ok {
			return "", false
		}
		attributeValue, ok := entitlement["attributeValue"].(string)
		return attributeValue, ok
	default:
		return "", false
	}
}

func validationCommands(plan planner.Plan) []Check {
	commands := []Check{}
	for _, app := range plan.Apps {
		switch app.Key {
		case planner.AppJWTService:
			certAlias := app.Name + "-cert"
			if len(app.OCICreatePayload.Certificates) > 0 {
				certAlias = app.OCICreatePayload.Certificates[0].CertAlias
			}
			commands = append(commands, Check{
				Key:     "jwt-client-credentials-" + app.Name,
				Status:  "manual",
				Message: "Validate JWT client assertion token issuance.",
				Command: "oci-context auth token --service " + shellQuote(string(plan.Target.Service)) +
					" --flow jwt-client-credentials --token-endpoint " + shellQuote(plan.Target.Issuer+"/oauth2/v1/token") +
					" --client-id " + shellQuote(app.Name) +
					" --scope " + shellQuote(plan.Target.Scope) +
					" --private-key-file '<private-key-file>' --key-id " + shellQuote(certAlias) +
					" --jwt-audience https://identity.oraclecloud.com/ --no-login --format raw >/dev/null",
			})
		case planner.AppService:
			commands = append(commands, Check{
				Key:     "client-credentials-" + app.Name,
				Status:  "manual",
				Message: "Validate client credentials token issuance.",
				Command: "oci-context auth token --service " + shellQuote(string(plan.Target.Service)) +
					" --flow client-credentials --issuer " + shellQuote(plan.Target.Issuer) +
					" --client-id " + shellQuote(app.Name) +
					" --client-secret '<client-secret>' --scope " + shellQuote(plan.Target.Scope) +
					" --no-login --format raw >/dev/null",
			})
		}
		if app.Principal != nil {
			commands = append(commands,
				Check{
					Key:     "principal-user-" + app.Name,
					Status:  "manual",
					Message: "Confirm the same-name principal user exists.",
					Command: "oci identity-domains users search --endpoint " + shellQuote(plan.Target.IDCSEndpoint) +
						" --schemas '[\"urn:ietf:params:scim:api:messages:2.0:SearchRequest\"]'" +
						" --filter " + shellQuote("userName eq \""+app.Principal.UserName+"\"") +
						" --attributes '[\"id\",\"userName\",\"displayName\",\"active\",\"roles\"]' --count 10",
				},
				Check{
					Key:     "principal-user-grants-" + app.Name,
					Status:  "manual",
					Message: "Confirm the same-name principal user has target service app-role grants.",
					Command: "oci identity-domains grants search --endpoint " + shellQuote(plan.Target.IDCSEndpoint) +
						" --schemas '[\"urn:ietf:params:scim:api:messages:2.0:SearchRequest\"]'" +
						" --filter " + shellQuote("grantee.value eq \"<principal-user-id-for-"+app.Name+">\"") +
						" --attributes '[\"id\",\"app\",\"entitlement\",\"grantee\",\"grantMechanism\",\"isFulfilled\"]' --count 100",
				},
			)
		}
	}
	return commands
}

func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\"'\"'") + "'"
}
