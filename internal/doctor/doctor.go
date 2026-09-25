package doctor

import (
	"encoding/json"
	"io"
	"os"
	"strings"

	"github.com/adrianmross/oci-idm/internal/handoff"
	"github.com/adrianmross/oci-idm/internal/planner"
	"github.com/adrianmross/oci-idm/internal/validation"
)

const SchemaVersion = "oci-idm.doctor.v1"

type Defaults struct {
	ContextName   string `json:"contextName,omitempty"`
	Profile       string `json:"profile,omitempty"`
	Region        string `json:"region,omitempty"`
	OCIConfigPath string `json:"ociConfigPath,omitempty"`
	ServiceName   string `json:"serviceName,omitempty"`
	Issuer        string `json:"issuer,omitempty"`
	Scope         string `json:"scope,omitempty"`
}

type Report struct {
	SchemaVersion string             `json:"schemaVersion"`
	Defaults      Defaults           `json:"defaults,omitempty"`
	Checks        []validation.Check `json:"checks"`
	Commands      []validation.Check `json:"commands,omitempty"`
}

func FromPlanFile(path string, defaults Defaults) (Report, error) {
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
	return FromPlan(plan, defaults), nil
}

func readPlanBytes(path string) ([]byte, error) {
	if strings.TrimSpace(path) == "-" {
		return io.ReadAll(os.Stdin)
	}
	return os.ReadFile(path)
}

func FromPlan(plan planner.Plan, defaults Defaults) Report {
	report := Report{SchemaVersion: SchemaVersion, Defaults: defaults}
	report.Checks = append(report.Checks, defaultsChecks(defaults)...)
	validationReport := validation.FromPlan(plan)
	report.Checks = append(report.Checks, validationReport.Checks...)
	report.Commands = append(report.Commands, validationReport.Commands...)

	if plan.Target.OCIProfile == "" {
		report.Checks = append(report.Checks, validation.Check{Key: "plan-oci-profile", Status: "warn", Severity: "warning", Message: "plan does not carry an OCI profile; generated OCI commands depend on ambient OCI CLI defaults"})
	} else {
		report.Checks = append(report.Checks, validation.Check{Key: "plan-oci-profile", Status: "pass", Message: "plan carries OCI profile " + plan.Target.OCIProfile})
	}
	ociContext := handoff.ForOCIContext(plan)
	if len(ociContext.TokenServices) == 0 {
		report.Checks = append(report.Checks, validation.Check{Key: "oci-context-handoff", Status: "warn", Severity: "warning", Message: "plan does not generate oci-context token services"})
	} else {
		report.Checks = append(report.Checks, validation.Check{Key: "oci-context-handoff", Status: "pass", Message: "plan generates " + itoa(len(ociContext.TokenServices)) + " token service(s)"})
	}
	return report
}

func FromDefaults(defaults Defaults) Report {
	return Report{SchemaVersion: SchemaVersion, Defaults: defaults, Checks: defaultsChecks(defaults)}
}

func defaultsChecks(defaults Defaults) []validation.Check {
	checks := []validation.Check{}
	add := func(key, status, severity, message string) {
		checks = append(checks, validation.Check{Key: key, Status: status, Severity: severity, Message: message})
	}
	if strings.TrimSpace(defaults.ContextName) == "" {
		add("oci-context-current", "warn", "warning", "no current oci-context was resolved")
	} else {
		add("oci-context-current", "pass", "", "current context is "+defaults.ContextName)
	}
	if strings.TrimSpace(defaults.Profile) == "" {
		add("oci-profile", "warn", "warning", "no OCI CLI profile was resolved")
	} else {
		add("oci-profile", "pass", "", "profile is "+defaults.Profile)
	}
	if strings.TrimSpace(defaults.OCIConfigPath) == "" {
		add("oci-config-file", "warn", "warning", "no OCI config file path was resolved")
	} else {
		add("oci-config-file", "pass", "", "config file is "+defaults.OCIConfigPath)
	}
	if strings.TrimSpace(defaults.ServiceName) != "" {
		if strings.TrimSpace(defaults.Issuer) == "" {
			add("token-service-issuer", "warn", "warning", "token service "+defaults.ServiceName+" did not resolve an issuer")
		} else {
			add("token-service-issuer", "pass", "", "issuer is set")
		}
		if strings.TrimSpace(defaults.Scope) == "" {
			add("token-service-scope", "warn", "warning", "token service "+defaults.ServiceName+" did not resolve a scope")
		} else {
			add("token-service-scope", "pass", "", "scope is set")
		}
	}
	return checks
}

func itoa(value int) string {
	if value == 0 {
		return "0"
	}
	digits := []byte{}
	for value > 0 {
		digits = append([]byte{byte('0' + value%10)}, digits...)
		value /= 10
	}
	return string(digits)
}
