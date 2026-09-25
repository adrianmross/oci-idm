package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/adrianmross/oci-idm/internal/applyexec"
	"github.com/adrianmross/oci-idm/internal/diagnose"
	"github.com/adrianmross/oci-idm/internal/discovery"
	"github.com/adrianmross/oci-idm/internal/doctor"
	"github.com/adrianmross/oci-idm/internal/handoff"
	"github.com/adrianmross/oci-idm/internal/materialize"
	"github.com/adrianmross/oci-idm/internal/obpeecp"
	"github.com/adrianmross/oci-idm/internal/planner"
	"github.com/adrianmross/oci-idm/internal/validation"
)

var (
	version        = "dev"
	commit         = "none"
	date           = "unknown"
	stdinReader    = io.Reader(os.Stdin)
	oidcHTTPClient = http.DefaultClient
)

func Run(args []string, stdout io.Writer, stderr io.Writer) int {
	return RunWithName("oci-idm", args, stdout, stderr)
}

func RunWithName(program string, args []string, stdout io.Writer, stderr io.Writer) int {
	if strings.TrimSpace(program) == "" {
		program = "oci-idm"
	}
	if len(args) == 0 {
		writeRootHelp(stdout, program)
		return 0
	}

	switch args[0] {
	case "help", "-h", "--help":
		writeRootHelp(stdout, program)
		return 0
	case "version", "-v", "--version":
		fmt.Fprintln(stdout, versionString())
		return 0
	case "get":
		if err := runGet(args[1:], stdout); err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
		return 0
	case "describe":
		if err := runDescribe(args[1:], stdout); err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
		return 0
	case "create":
		if len(args) > 1 && isResource(args[1], "domain", "domains") {
			if err := runApplyDomain(args[2:], stdout); err != nil {
				fmt.Fprintln(stderr, err)
				return 1
			}
			return 0
		}
		if len(args) > 1 && isResource(args[1], "app-role-assignment", "app-role-assignments") {
			if err := runAssignAppRole(args[2:], stdout); err != nil {
				fmt.Fprintln(stderr, err)
				return 1
			}
			return 0
		}
		fmt.Fprintln(stderr, "create requires a resource: domain or app-role-assignment")
		return 1
	case "edit":
		commandArgs, err := stripResourceArg(args[1:], "app", "service-app", "resource-app", "identity-app")
		if err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
		if err := runPatchApp(commandArgs, stdout); err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
		return 0
	case "plan":
		if len(args) > 1 && isResource(args[1], "domain", "domains") {
			if err := runPlanDomain(args[2:], stdout); err != nil {
				fmt.Fprintln(stderr, err)
				return 1
			}
			return 0
		}
		commandArgs, err := stripResourceArg(args[1:], "app", "apps", "identity-app", "identity-apps")
		if err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
		if err := runPlan(commandArgs, stdout); err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
		return 0
	case "export":
		if err := runExport(args[1:], stdout); err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
		return 0
	case "clone":
		commandArgs, err := stripResourceArg(args[1:], "app", "apps", "identity-app", "identity-apps")
		if err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
		if err := runClone(commandArgs, stdout); err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
		return 0
	case "patch":
		commandArgs, err := stripResourceArg(args[1:], "app", "service-app", "resource-app", "identity-app")
		if err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
		if err := runPatchApp(commandArgs, stdout); err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
		return 0
	case "assign":
		commandArgs, err := stripResourceArg(args[1:], "app-role", "app-roles")
		if err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
		if err := runAssignAppRole(commandArgs, stdout); err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
		return 0
	case "defaults", "context":
		if err := runDefaults(args[1:], stdout); err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
		return 0
	case "discover":
		if err := runDiscover(args[1:], stdout); err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
		return 0
	case "diagnose":
		commandArgs, err := stripResourceArg(args[1:], "app", "apps", "service-app", "service-apps", "identity-app", "identity-apps")
		if err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
		if err := runDiagnose(commandArgs, stdout); err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
		return 0
	case "materialize":
		commandArgs, err := stripResourceArg(args[1:], "plan", "plans")
		if err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
		if err := runMaterialize(commandArgs, stdout); err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
		return 0
	case "apply":
		if len(args) > 1 && isResource(args[1], "domain", "domains") {
			if err := runApplyDomain(args[2:], stdout); err != nil {
				fmt.Fprintln(stderr, err)
				return 1
			}
			return 0
		}
		commandArgs, err := stripResourceArg(args[1:], "plan", "plans")
		if err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
		if err := runApply(commandArgs, stdout); err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
		return 0
	case "validate":
		commandArgs, err := stripResourceArg(args[1:], "plan", "plans")
		if err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
		if err := runValidate(commandArgs, stdout); err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
		return 0
	case "doctor":
		commandArgs, err := stripResourceArg(args[1:], "plan", "plans", "context", "contexts")
		if err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
		if err := runDoctor(commandArgs, stdout); err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
		return 0
	case "handoff":
		if err := runHandoff(args[1:], stdout); err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
		return 0
	default:
		fmt.Fprintf(stderr, "unknown command %q\n", args[0])
		return 1
	}
}

func isResource(value string, allowed ...string) bool {
	value = strings.ToLower(strings.TrimSpace(value))
	for _, candidate := range allowed {
		if value == candidate {
			return true
		}
	}
	return false
}

func runGet(args []string, stdout io.Writer) error {
	if len(args) == 0 || strings.HasPrefix(args[0], "-") {
		return fmt.Errorf("get requires a resource: defaults, domains, services, service-apps, or apps")
	}
	resource := strings.ToLower(strings.TrimSpace(args[0]))
	commandArgs := args[1:]
	switch resource {
	case "defaults", "default", "context", "contexts":
		return runDefaults(commandArgs, stdout)
	case "domain", "domains":
		return runDomains(commandArgs, stdout, false)
	case "service", "services", "token-service", "token-services":
		return runServices(commandArgs, stdout)
	case "app", "apps", "service-app", "service-apps", "resource-app", "resource-apps", "identity-app", "identity-apps":
		return runDiscover(commandArgs, stdout)
	default:
		return fmt.Errorf("unsupported get resource %q", args[0])
	}
}

func runDescribe(args []string, stdout io.Writer) error {
	if len(args) == 0 || strings.HasPrefix(args[0], "-") {
		return fmt.Errorf("describe requires a resource: domain, service-app, or app")
	}
	resource := strings.ToLower(strings.TrimSpace(args[0]))
	commandArgs := args[1:]
	switch resource {
	case "domain", "domains":
		return runDomains(commandArgs, stdout, true)
	case "app", "apps", "service-app", "service-apps", "resource-app", "resource-apps", "identity-app", "identity-apps":
		return runDiscover(commandArgs, stdout)
	default:
		return fmt.Errorf("unsupported describe resource %q", args[0])
	}
}

type domainDiscoveryPlan struct {
	SchemaVersion   string `json:"schemaVersion"`
	Action          string `json:"action"`
	ContextName     string `json:"contextName,omitempty"`
	TenancyOCID     string `json:"tenancyOcid,omitempty"`
	CompartmentOCID string `json:"compartmentOcid,omitempty"`
	DomainID        string `json:"domainId,omitempty"`
	Command         string `json:"command"`
}

func runDomains(args []string, stdout io.Writer, requireDomainID bool) error {
	flags := flag.NewFlagSet("domains", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	domainID := flags.String("domain-id", "", "OCI Identity Domain OCID for describe")
	compartmentID := flags.String("compartment-id", "", "OCI compartment OCID for list; defaults from current oci-context")
	profile := flags.String("profile", "", "OCI CLI profile for generated commands; defaults from current oci-context or OCI_CLI_PROFILE")
	ociConfigPath := flags.String("oci-config-file", "", "OCI CLI config file for generated commands; defaults from current oci-context or OCI_CLI_CONFIG_FILE")
	region := flags.String("region", "", "OCI region for generated commands; defaults from current oci-context or OCI_CLI_REGION")
	useOCIContext := flags.Bool("oci-context", true, "read current oci-context defaults for omitted values")
	ociContextBin := flags.String("oci-context-bin", "oci-context", "oci-context binary used for defaults")
	var output string
	addOutputFlags(flags, &output, "json", "output format: json or text")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() > 0 {
		return fmt.Errorf("unexpected argument %q", flags.Arg(0))
	}
	defaults := ociContextDefaults{}
	if *useOCIContext {
		defaults = loadOCIContextDefaults(*ociContextBin, "")
		*profile = firstNonEmpty(*profile, defaults.Profile)
		*ociConfigPath = firstNonEmpty(*ociConfigPath, defaults.OCIConfigPath)
		*region = firstNonEmpty(*region, defaults.Region)
		*compartmentID = firstNonEmpty(*compartmentID, defaults.CompartmentOCID, defaults.TenancyOCID)
	}
	if requireDomainID && strings.TrimSpace(*domainID) == "" {
		return fmt.Errorf("--domain-id is required when describing a domain")
	}

	parts := []string{"oci", "iam", "domain"}
	action := "list"
	if strings.TrimSpace(*domainID) != "" {
		action = "get"
		parts = append(parts, action, "--domain-id", shellQuote(*domainID))
	} else {
		if strings.TrimSpace(*compartmentID) == "" {
			return fmt.Errorf("--compartment-id is required when no current oci-context compartment or tenancy is available")
		}
		parts = append(parts, action, "--compartment-id", shellQuote(*compartmentID))
	}
	if strings.TrimSpace(*profile) != "" {
		parts = append(parts, "--profile", shellQuote(*profile))
	}
	if strings.TrimSpace(*ociConfigPath) != "" {
		parts = append(parts, "--config-file", shellQuote(*ociConfigPath))
	}
	if strings.TrimSpace(*region) != "" {
		parts = append(parts, "--region", shellQuote(*region))
	}
	plan := domainDiscoveryPlan{
		SchemaVersion: "oci-idm.domains.v1", Action: action, ContextName: defaults.ContextName,
		TenancyOCID: defaults.TenancyOCID, CompartmentOCID: *compartmentID,
		DomainID: *domainID, Command: strings.Join(parts, " "),
	}
	switch strings.ToLower(strings.TrimSpace(output)) {
	case "json":
		encoder := json.NewEncoder(stdout)
		encoder.SetIndent("", "  ")
		return encoder.Encode(plan)
	case "text":
		fmt.Fprintf(stdout, "action: %s\n", plan.Action)
		if plan.ContextName != "" {
			fmt.Fprintf(stdout, "context: %s\n", plan.ContextName)
		}
		if plan.CompartmentOCID != "" {
			fmt.Fprintf(stdout, "compartment: %s\n", plan.CompartmentOCID)
		}
		if plan.DomainID != "" {
			fmt.Fprintf(stdout, "domainId: %s\n", plan.DomainID)
		}
		fmt.Fprintf(stdout, "command: %s\n", plan.Command)
		return nil
	default:
		return fmt.Errorf("unsupported output %q", output)
	}
}

func runServices(args []string, stdout io.Writer) error {
	flags := flag.NewFlagSet("services", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	ociContextBin := flags.String("oci-context-bin", "oci-context", "oci-context binary used to list token services")
	var output string
	addOutputFlags(flags, &output, "json", "output format: json or text")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() > 0 {
		return fmt.Errorf("unexpected argument %q", flags.Arg(0))
	}
	data, err := runCommand(*ociContextBin, "auth", "service", "list", "-o", "json")
	if err != nil {
		return fmt.Errorf("list oci-context token services: %w", err)
	}
	var services []ociContextTokenService
	if err := json.Unmarshal(data, &services); err != nil {
		return fmt.Errorf("decode oci-context token services: %w", err)
	}
	switch strings.ToLower(strings.TrimSpace(output)) {
	case "json":
		encoder := json.NewEncoder(stdout)
		encoder.SetIndent("", "  ")
		return encoder.Encode(services)
	case "text":
		for _, service := range services {
			fmt.Fprintf(stdout, "%s\n  issuer: %s\n  scope: %s\n", service.Name, service.Issuer, service.Scope)
		}
		return nil
	default:
		return fmt.Errorf("unsupported output %q", output)
	}
}

func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\"'\"'") + "'"
}

func commandString(name string, args ...string) string {
	parts := []string{name}
	for _, arg := range args {
		parts = append(parts, shellQuote(arg))
	}
	return strings.Join(parts, " ")
}

const domainPlanSchemaVersion = "oci-idm.domain-plan.v1"

type domainCreatePlan struct {
	SchemaVersion       string `json:"schemaVersion"`
	ContextName         string `json:"contextName,omitempty"`
	CompartmentOCID     string `json:"compartmentOcid"`
	DisplayName         string `json:"displayName"`
	Description         string `json:"description"`
	HomeRegion          string `json:"homeRegion"`
	LicenseType         string `json:"licenseType"`
	Profile             string `json:"profile,omitempty"`
	OCIConfigPath       string `json:"ociConfigPath,omitempty"`
	Region              string `json:"region,omitempty"`
	MaxWaitSeconds      int    `json:"maxWaitSeconds"`
	WaitIntervalSeconds int    `json:"waitIntervalSeconds"`
	Command             string `json:"command"`
}

type domainApplyResult struct {
	SchemaVersion  string `json:"schemaVersion"`
	Status         string `json:"status"`
	DomainID       string `json:"domainId,omitempty"`
	LifecycleState string `json:"lifecycleState,omitempty"`
	Command        string `json:"command"`
}

func runPlanDomain(args []string, stdout io.Writer) error {
	flags := flag.NewFlagSet("plan domain", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	var displayName string
	flags.StringVar(&displayName, "name", "", "Identity Domain display name")
	flags.StringVar(&displayName, "display-name", "", "Identity Domain display name")
	description := flags.String("description", "", "Identity Domain description")
	licenseType := flags.String("license-type", "", "Identity Domain license type")
	homeRegion := flags.String("home-region", "", "Identity Domain home region; defaults from current oci-context")
	compartmentID := flags.String("compartment-id", "", "OCI compartment OCID; defaults from current oci-context")
	profile := flags.String("profile", "", "OCI CLI profile; defaults from current oci-context or OCI_CLI_PROFILE")
	ociConfigPath := flags.String("oci-config-file", "", "OCI CLI config file; defaults from current oci-context or OCI_CLI_CONFIG_FILE")
	region := flags.String("region", "", "OCI region; defaults from current oci-context or OCI_CLI_REGION")
	maxWaitSeconds := flags.Int("max-wait-seconds", 1200, "maximum seconds to wait for the domain to become active")
	waitIntervalSeconds := flags.Int("wait-interval-seconds", 30, "seconds between lifecycle checks")
	useOCIContext := flags.Bool("oci-context", true, "read current oci-context defaults for omitted values")
	ociContextBin := flags.String("oci-context-bin", "oci-context", "oci-context binary used for defaults")
	var output string
	addOutputFlags(flags, &output, "json", "output format: json or text")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() > 0 {
		return fmt.Errorf("unexpected argument %q", flags.Arg(0))
	}
	defaults := ociContextDefaults{}
	if *useOCIContext {
		defaults = loadOCIContextDefaults(*ociContextBin, "")
		*compartmentID = firstNonEmpty(*compartmentID, defaults.CompartmentOCID, defaults.TenancyOCID)
		*profile = firstNonEmpty(*profile, defaults.Profile)
		*ociConfigPath = firstNonEmpty(*ociConfigPath, defaults.OCIConfigPath)
		*region = firstNonEmpty(*region, defaults.Region)
		*homeRegion = firstNonEmpty(*homeRegion, defaults.Region)
	}
	for field, value := range map[string]string{
		"--name/--display-name": displayName,
		"--description":         *description,
		"--license-type":        *licenseType,
		"--home-region":         *homeRegion,
		"--compartment-id":      *compartmentID,
	} {
		if strings.TrimSpace(value) == "" {
			return fmt.Errorf("%s is required", field)
		}
	}
	if *maxWaitSeconds <= 0 || *waitIntervalSeconds <= 0 {
		return fmt.Errorf("--max-wait-seconds and --wait-interval-seconds must be positive")
	}
	plan := domainCreatePlan{
		SchemaVersion: domainPlanSchemaVersion, ContextName: defaults.ContextName,
		CompartmentOCID: *compartmentID, DisplayName: displayName, Description: *description,
		HomeRegion: *homeRegion, LicenseType: *licenseType, Profile: *profile,
		OCIConfigPath: *ociConfigPath, Region: *region, MaxWaitSeconds: *maxWaitSeconds,
		WaitIntervalSeconds: *waitIntervalSeconds,
	}
	plan.Command = commandString("oci", domainCreateArgs(plan)...)
	return writeDomainPlan(stdout, plan, output)
}

func domainCreateArgs(plan domainCreatePlan) []string {
	args := []string{
		"iam", "domain", "create",
		"--compartment-id", plan.CompartmentOCID,
		"--display-name", plan.DisplayName,
		"--description", plan.Description,
		"--home-region", plan.HomeRegion,
		"--license-type", plan.LicenseType,
		"--wait-for-state", "SUCCEEDED",
		"--max-wait-seconds", fmt.Sprint(plan.MaxWaitSeconds),
	}
	return appendDomainCLIOverrides(args, plan)
}

func domainGetArgs(plan domainCreatePlan, domainID string) []string {
	return appendDomainCLIOverrides([]string{"iam", "domain", "get", "--domain-id", domainID}, plan)
}

func domainListArgs(plan domainCreatePlan) []string {
	return appendDomainCLIOverrides([]string{"iam", "domain", "list", "--compartment-id", plan.CompartmentOCID}, plan)
}

func appendDomainCLIOverrides(args []string, plan domainCreatePlan) []string {
	if plan.Profile != "" {
		args = append(args, "--profile", plan.Profile)
	}
	if plan.OCIConfigPath != "" {
		args = append(args, "--config-file", plan.OCIConfigPath)
	}
	if plan.Region != "" {
		args = append(args, "--region", plan.Region)
	}
	return args
}

func writeDomainPlan(stdout io.Writer, plan domainCreatePlan, output string) error {
	switch strings.ToLower(strings.TrimSpace(output)) {
	case "json":
		encoder := json.NewEncoder(stdout)
		encoder.SetIndent("", "  ")
		return encoder.Encode(plan)
	case "text":
		fmt.Fprintf(stdout, "name: %s\ncompartment: %s\nhomeRegion: %s\nlicenseType: %s\ncommand: %s\n", plan.DisplayName, plan.CompartmentOCID, plan.HomeRegion, plan.LicenseType, plan.Command)
		return nil
	default:
		return fmt.Errorf("unsupported output %q", output)
	}
}

func runApplyDomain(args []string, stdout io.Writer) error {
	flags := flag.NewFlagSet("apply domain", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	var planPath string
	addFileFlags(flags, &planPath, "path to a JSON plan emitted by oci-idm plan domain")
	execute := flags.Bool("execute", false, "deprecated compatibility flag; use --apply")
	apply := flags.Bool("apply", false, "create the domain after preview")
	confirm := flags.Bool("confirm", false, "deprecated alias for --apply")
	var output string
	addOutputFlags(flags, &output, "text", "output format: json or text")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() > 0 {
		return fmt.Errorf("unexpected argument %q", flags.Arg(0))
	}
	if strings.TrimSpace(planPath) == "" {
		return fmt.Errorf("-f/--file is required")
	}
	if *execute && !*apply && !*confirm {
		return fmt.Errorf("--execute requires --apply")
	}
	plan, err := readDomainPlan(planPath)
	if err != nil {
		return err
	}
	if !*apply && !*confirm {
		return writeDomainApplyResult(stdout, domainApplyResult{SchemaVersion: "oci-idm.domain-apply.v1", Status: "planned", Command: plan.Command}, output)
	}
	if existingID, err := findExistingDomain(plan); err != nil {
		return err
	} else if existingID != "" {
		state, err := waitForDomainActive(plan, existingID)
		if err != nil {
			return err
		}
		return writeDomainApplyResult(stdout, domainApplyResult{SchemaVersion: "oci-idm.domain-apply.v1", Status: "reused", DomainID: existingID, LifecycleState: state, Command: plan.Command}, output)
	}
	out, err := runCommand("oci", domainCreateArgs(plan)...)
	if err != nil {
		return fmt.Errorf("create identity domain: %w", err)
	}
	domainID := responseID(out)
	if domainID == "" {
		return fmt.Errorf("create identity domain returned no domain id")
	}
	state, err := waitForDomainActive(plan, domainID)
	if err != nil {
		return err
	}
	return writeDomainApplyResult(stdout, domainApplyResult{SchemaVersion: "oci-idm.domain-apply.v1", Status: "created", DomainID: domainID, LifecycleState: state, Command: plan.Command}, output)
}

func readDomainPlan(path string) (domainCreatePlan, error) {
	var data []byte
	var err error
	if strings.TrimSpace(path) == "-" {
		data, err = io.ReadAll(stdinReader)
	} else {
		data, err = os.ReadFile(path)
	}
	if err != nil {
		return domainCreatePlan{}, err
	}
	var plan domainCreatePlan
	if err := json.Unmarshal(data, &plan); err != nil {
		return domainCreatePlan{}, err
	}
	if plan.SchemaVersion != domainPlanSchemaVersion {
		return domainCreatePlan{}, fmt.Errorf("unsupported domain plan schema %q", plan.SchemaVersion)
	}
	if plan.DisplayName == "" || plan.Description == "" || plan.HomeRegion == "" || plan.LicenseType == "" || plan.CompartmentOCID == "" || plan.MaxWaitSeconds <= 0 || plan.WaitIntervalSeconds <= 0 {
		return domainCreatePlan{}, fmt.Errorf("domain plan is incomplete")
	}
	plan.Command = commandString("oci", domainCreateArgs(plan)...)
	return plan, nil
}

func findExistingDomain(plan domainCreatePlan) (string, error) {
	out, err := runCommand("oci", domainListArgs(plan)...)
	if err != nil {
		return "", fmt.Errorf("list identity domains before create: %w", err)
	}
	return domainIDByDisplayName(out, plan.DisplayName), nil
}

func domainIDByDisplayName(data []byte, displayName string) string {
	var value any
	if json.Unmarshal(data, &value) != nil {
		return ""
	}
	return findDomainID(value, displayName)
}

func responseID(data []byte) string {
	var value any
	if json.Unmarshal(data, &value) != nil {
		return ""
	}
	return findResponseID(value)
}

func findResponseID(value any) string {
	switch item := value.(type) {
	case map[string]any:
		if id := stringValue(item["id"]); id != "" {
			return id
		}
		for _, child := range item {
			if id := findResponseID(child); id != "" {
				return id
			}
		}
	case []any:
		for _, child := range item {
			if id := findResponseID(child); id != "" {
				return id
			}
		}
	}
	return ""
}

func findDomainID(value any, displayName string) string {
	switch item := value.(type) {
	case map[string]any:
		name := firstNonEmpty(stringValue(item["display-name"]), stringValue(item["displayName"]))
		if name == displayName {
			return stringValue(item["id"])
		}
		for _, child := range item {
			if id := findDomainID(child, displayName); id != "" {
				return id
			}
		}
	case []any:
		for _, child := range item {
			if id := findDomainID(child, displayName); id != "" {
				return id
			}
		}
	}
	return ""
}

func waitForDomainActive(plan domainCreatePlan, domainID string) (string, error) {
	deadline := time.Now().Add(time.Duration(plan.MaxWaitSeconds) * time.Second)
	for {
		out, err := runCommand("oci", domainGetArgs(plan, domainID)...)
		if err != nil {
			return "", fmt.Errorf("get identity domain %s: %w", domainID, err)
		}
		state := domainLifecycleState(out)
		if state == "ACTIVE" {
			return state, nil
		}
		if state == "FAILED" || state == "INACTIVE" {
			return state, fmt.Errorf("identity domain %s reached %s", domainID, state)
		}
		if time.Now().After(deadline) {
			return state, fmt.Errorf("identity domain %s did not become ACTIVE before timeout (last state %q)", domainID, state)
		}
		time.Sleep(time.Duration(plan.WaitIntervalSeconds) * time.Second)
	}
}

func domainLifecycleState(data []byte) string {
	var value any
	if json.Unmarshal(data, &value) != nil {
		return ""
	}
	return findLifecycleState(value)
}

func findLifecycleState(value any) string {
	switch item := value.(type) {
	case map[string]any:
		if state := firstNonEmpty(stringValue(item["lifecycle-state"]), stringValue(item["lifecycleState"])); state != "" {
			return strings.ToUpper(state)
		}
		for _, child := range item {
			if state := findLifecycleState(child); state != "" {
				return state
			}
		}
	case []any:
		for _, child := range item {
			if state := findLifecycleState(child); state != "" {
				return state
			}
		}
	}
	return ""
}

func stringValue(value any) string {
	text, _ := value.(string)
	return text
}

func writeDomainApplyResult(stdout io.Writer, result domainApplyResult, output string) error {
	switch strings.ToLower(strings.TrimSpace(output)) {
	case "json":
		encoder := json.NewEncoder(stdout)
		encoder.SetIndent("", "  ")
		return encoder.Encode(result)
	case "text":
		fmt.Fprintf(stdout, "%s: domain", result.Status)
		if result.DomainID != "" {
			fmt.Fprintf(stdout, " id=%s", result.DomainID)
		}
		if result.LifecycleState != "" {
			fmt.Fprintf(stdout, " lifecycle=%s", result.LifecycleState)
		}
		fmt.Fprintf(stdout, "\ncommand: %s\n", result.Command)
		return nil
	default:
		return fmt.Errorf("unsupported output %q", output)
	}
}

func stripResourceArg(args []string, allowed ...string) ([]string, error) {
	if len(args) == 0 || strings.HasPrefix(args[0], "-") {
		return args, nil
	}
	resource := strings.ToLower(strings.TrimSpace(args[0]))
	for _, value := range allowed {
		if resource == value {
			return args[1:], nil
		}
	}
	return nil, fmt.Errorf("unsupported resource %q", args[0])
}

func runDefaults(args []string, stdout io.Writer) error {
	flags := flag.NewFlagSet("defaults", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	service := flags.String("service", "", "service preset used for token-service defaults; defaults from current oci-context else obp")
	ociContextService := flags.String("oci-context-service", "", "oci-context token service name; defaults from --service")
	ociContextBin := flags.String("oci-context-bin", "oci-context", "oci-context binary used for defaults")
	var output string
	addOutputFlags(flags, &output, "json", "output format: json or text")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() > 0 {
		return fmt.Errorf("unexpected argument %q", flags.Arg(0))
	}
	defaults := resolvedDoctorDefaults(*ociContextBin, *service, *ociContextService)
	return printDefaults(stdout, defaults, output)
}

func addOutputFlags(flags *flag.FlagSet, output *string, defaultValue string, usage string) {
	flags.StringVar(output, "output", defaultValue, usage)
	flags.StringVar(output, "o", defaultValue, usage+" (shorthand)")
	flags.StringVar(output, "format", defaultValue, usage+" (alias)")
}

func addFileFlags(flags *flag.FlagSet, path *string, usage string) {
	flags.StringVar(path, "file", "", usage)
	flags.StringVar(path, "f", "", usage+" (shorthand)")
	flags.StringVar(path, "plan", "", usage+" (alias)")
}

func versionString() string {
	parts := []string{version}
	if commit != "" && commit != "none" {
		parts = append(parts, "commit="+commit)
	}
	if date != "" && date != "unknown" {
		parts = append(parts, "built="+date)
	}
	return strings.Join(parts, " ")
}

func runPlan(args []string, stdout io.Writer) error {
	flags := flag.NewFlagSet("plan", flag.ContinueOnError)
	flags.SetOutput(io.Discard)

	service := flags.String("service", "", "service preset: generic or obp; defaults from current oci-context else generic")
	platform := flags.String("platform", "", "target service platform URL")
	issuer := flags.String("issuer", "", "OCI Identity Domains issuer URL")
	scope := flags.String("scope", "", "OAuth scope; defaults to --platform for --service obp")
	idcsEndpoint := flags.String("idcs-endpoint", "", "OCI Identity Domains base endpoint")
	resourceAppID := flags.String("resource-app-id", "", "target service/resource app id that defines the requested scope")
	baseAppName := flags.String("base-app-name", "", "service-created app name to document as source context")
	baseAppDisplayName := flags.String("base-app-display-name", "", "service-created app display name")
	appPrefix := flags.String("app-prefix", "", "prefix for generated companion app names")
	redirectURL := flags.String("redirect-url", planner.DefaultCLIRedirectURL, "loopback redirect URL for CLI auth-code flow")
	include := flags.String("include", "user,service,jwt", "comma list of apps to plan: user,service,jwt,jwt-service,jwt-user,workload")
	userClientType := flags.String("user-client-type", string(planner.ClientPublic), "user app client type: public or confidential")
	principalMode := flags.String("principal-mode", string(planner.PrincipalAuto), "service principal mode: auto, none, or same-name-user")
	principalEmailDomain := flags.String("principal-email-domain", "example.invalid", "email domain for generated same-name principal users")
	rolePreset := flags.String("role-preset", "none", "comma list of service role presets: none,obp-admin,obp-rest-client,obp-user,obp-ca-user")
	appRoleGrants := flags.String("app-role-grants", "", "comma list of target service app role grants as NAME=APP_ROLE_ID entries")
	certificateAlias := flags.String("certificate-alias", "", "certificate alias for JWT client assertion apps; defaults to <app-name>-cert")
	templateID := flags.String("template-id", "", "template id override for all planned apps")
	userTemplateID := flags.String("user-template-id", "", "template id for the user app")
	serviceTemplateID := flags.String("service-template-id", "", "template id for the service app")
	jwtTemplateID := flags.String("jwt-template-id", "", "template id for the JWT assertion app")
	accessTokenExpiry := flags.Int("access-token-expiry", 0, "optional access token expiry in seconds")
	refreshTokenExpiry := flags.Int("refresh-token-expiry", 0, "optional refresh token expiry in seconds")
	profile := flags.String("profile", "", "OCI CLI profile for generated Identity Domains commands; defaults from current oci-context")
	ociConfigPath := flags.String("oci-config-file", "", "OCI CLI config file for generated commands; defaults from current oci-context")
	region := flags.String("region", "", "OCI region for generated commands; defaults from current oci-context")
	useOCIContext := flags.Bool("oci-context", true, "read current oci-context and token-service defaults for omitted values")
	ociContextBin := flags.String("oci-context-bin", "oci-context", "oci-context binary used for defaults")
	ociContextService := flags.String("oci-context-service", "", "oci-context token service used for issuer/scope defaults; defaults to --service for non-generic services")
	var output string
	addOutputFlags(flags, &output, "json", "output format: json, text, oci-context-yaml, oci-context-json, commands, ochain-env, ochain-dotenv, or ochain-json")
	tokenService := flags.String("token-service", "", "token service name for OChain output")

	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() > 0 {
		return fmt.Errorf("unexpected argument %q", flags.Arg(0))
	}

	includes, err := planner.ParseIncludes(*include)
	if err != nil {
		return err
	}
	clientType, err := planner.ParseClientType(*userClientType)
	if err != nil {
		return err
	}
	parsedPrincipalMode, err := planner.ParsePrincipalMode(*principalMode)
	if err != nil {
		return err
	}
	grants, err := planner.ParseAppRoleGrants(*appRoleGrants)
	if err != nil {
		return err
	}
	presets, err := planner.ParseRolePresets(*rolePreset)
	if err != nil {
		return err
	}
	visited := collectVisitedFlags(flags)
	contextName := ""
	if *useOCIContext {
		serviceName := firstNonEmpty(*ociContextService, defaultOCIContextServiceName(*service))
		defaults := loadOCIContextDefaults(*ociContextBin, serviceName)
		contextName = defaults.ContextName
		if !explicitFlags(visited, "issuer") && strings.TrimSpace(*issuer) == "" {
			*issuer = defaults.Issuer
		}
		if !explicitFlags(visited, "scope") && strings.TrimSpace(*scope) == "" {
			*scope = defaults.Scope
		}
		if !explicitFlags(visited, "service") && strings.TrimSpace(*service) == "" {
			*service = string(inferServiceKind(defaults, planner.ServiceGeneric))
		}
		if !explicitFlags(visited, "platform") && strings.TrimSpace(*platform) == "" && planner.ServiceKind(*service) == planner.ServiceOBP {
			*platform = defaults.Scope
		}
		if !explicitFlags(visited, "profile") && strings.TrimSpace(*profile) == "" {
			*profile = defaults.Profile
		}
		if !explicitFlags(visited, "oci-config-file") && strings.TrimSpace(*ociConfigPath) == "" {
			*ociConfigPath = defaults.OCIConfigPath
		}
		if !explicitFlags(visited, "region") && strings.TrimSpace(*region) == "" {
			*region = defaults.Region
		}
	}
	plan, err := planner.Build(planner.Options{
		Service:              planner.ServiceKind(*service),
		Platform:             *platform,
		Issuer:               *issuer,
		Scope:                *scope,
		IDCSEndpoint:         *idcsEndpoint,
		ResourceAppID:        *resourceAppID,
		BaseAppName:          *baseAppName,
		BaseAppDisplayName:   *baseAppDisplayName,
		AppPrefix:            *appPrefix,
		RedirectURL:          *redirectURL,
		Include:              includes,
		UserClientType:       clientType,
		PrincipalMode:        parsedPrincipalMode,
		PrincipalEmailDomain: *principalEmailDomain,
		RolePresets:          presets,
		AppRoleGrants:        grants,
		CertificateAlias:     *certificateAlias,
		TemplateID:           *templateID,
		UserTemplateID:       *userTemplateID,
		ServiceTemplateID:    *serviceTemplateID,
		JWTTemplateID:        *jwtTemplateID,
		AccessTokenExpiry:    *accessTokenExpiry,
		RefreshTokenExpiry:   *refreshTokenExpiry,
		OCIContext:           contextName,
		OCIProfile:           *profile,
		OCIConfigPath:        *ociConfigPath,
		OCIRegion:            *region,
	})
	if err != nil {
		return err
	}

	return printPlanOutput(stdout, plan, output, *tokenService)
}

func runExport(args []string, stdout io.Writer) error {
	flags := flag.NewFlagSet("export", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	domain := flags.String("domain", "", "Identity Domains issuer URL")
	app := flags.String("app", "", "Identity Domains OAuth client ID")
	controlPlaneURL := flags.String("control-plane-url", "", "Control Plane base URL")
	redirectURI := flags.String("redirect-uri", "", "Control Plane OAuth callback URL; defaults from --control-plane-url")
	policyPath := flags.String("policy", "", "path to secret-free OBPEE Control Plane policy JSON")
	shape := flags.String("shape", "", "render target: obpee-cp")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() > 0 {
		return fmt.Errorf("unexpected argument %q", flags.Arg(0))
	}
	if strings.ToLower(strings.TrimSpace(*shape)) != "obpee-cp" {
		return fmt.Errorf("--shape obpee-cp is required")
	}
	if strings.TrimSpace(*domain) == "" || strings.TrimSpace(*app) == "" || strings.TrimSpace(*controlPlaneURL) == "" || strings.TrimSpace(*policyPath) == "" {
		return fmt.Errorf("--domain, --app, --control-plane-url, and --policy are required")
	}
	if strings.TrimSpace(*redirectURI) == "" {
		*redirectURI = strings.TrimRight(strings.TrimSpace(*controlPlaneURL), "/") + "/api/v1/auth/provider/code"
	}
	policy, err := readOBPEEPolicy(*policyPath)
	if err != nil {
		return err
	}
	wellKnownURI, err := obpeecp.WellKnownURI(*domain)
	if err != nil {
		return err
	}
	discovery, err := fetchOIDCDiscovery(wellKnownURI)
	if err != nil {
		return err
	}
	document, err := obpeecp.Build(obpeecp.Input{
		Domain: *domain, App: *app, ControlPlaneURL: *controlPlaneURL, RedirectURI: *redirectURI,
		Policy: policy, Discovery: discovery,
	})
	if err != nil {
		return err
	}
	encoder := json.NewEncoder(stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(document)
}

func readOBPEEPolicy(path string) (obpeecp.Policy, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return obpeecp.Policy{}, err
	}
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	var policy obpeecp.Policy
	if err := decoder.Decode(&policy); err != nil {
		return obpeecp.Policy{}, fmt.Errorf("decode policy: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return obpeecp.Policy{}, fmt.Errorf("decode policy: expected one JSON object")
	}
	return policy, nil
}

func fetchOIDCDiscovery(wellKnownURI string) (obpeecp.Discovery, error) {
	request, err := http.NewRequest(http.MethodGet, wellKnownURI, nil)
	if err != nil {
		return obpeecp.Discovery{}, err
	}
	response, err := oidcHTTPClient.Do(request)
	if err != nil {
		return obpeecp.Discovery{}, fmt.Errorf("fetch OIDC discovery: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return obpeecp.Discovery{}, fmt.Errorf("fetch OIDC discovery: HTTP %d", response.StatusCode)
	}
	var discovery obpeecp.Discovery
	if err := json.NewDecoder(response.Body).Decode(&discovery); err != nil {
		return obpeecp.Discovery{}, fmt.Errorf("decode OIDC discovery: %w", err)
	}
	return discovery, nil
}

func runClone(args []string, stdout io.Writer) error {
	flags := flag.NewFlagSet("clone", flag.ContinueOnError)
	flags.SetOutput(io.Discard)

	flow := flags.String("flow", "authorization-code", "auth flow: authorization-code, client-credentials, jwt-client-credentials, jwt-bearer, or token-exchange")
	name := flags.String("name", "", "exact Identity Domains app name and oci-context token service name")
	service := flags.String("service", "", "service preset: generic or obp; defaults from current oci-context when available")
	platform := flags.String("platform", "", "target service platform URL")
	issuer := flags.String("issuer", "", "OCI Identity Domains issuer URL")
	scope := flags.String("scope", "", "OAuth scope; defaults to --platform for OBP")
	idcsEndpoint := flags.String("idcs-endpoint", "", "OCI Identity Domains base endpoint")
	resourceAppID := flags.String("resource-app-id", "", "target service/resource app id that defines the requested scope")
	baseAppName := flags.String("base-app-name", "", "service-created app name to document as source context")
	baseAppDisplayName := flags.String("base-app-display-name", "", "service-created app display name")
	redirectURL := flags.String("redirect-url", planner.DefaultCLIRedirectURL, "loopback redirect URL for CLI auth-code flow")
	userClientType := flags.String("user-client-type", string(planner.ClientPublic), "authorization-code app client type: public or confidential")
	principalMode := flags.String("principal-mode", string(planner.PrincipalAuto), "service principal mode: auto, none, or same-name-user")
	principalEmailDomain := flags.String("principal-email-domain", "example.invalid", "email domain for generated same-name principal users")
	rolePreset := flags.String("role-preset", "none", "comma list of service role presets: none,obp-admin,obp-rest-client,obp-user,obp-ca-user")
	appRoleGrants := flags.String("app-role-grants", "", "comma list of target service app role grants as NAME=APP_ROLE_ID entries")
	profile := flags.String("profile", "", "OCI CLI profile for generated Identity Domains commands; defaults from current oci-context")
	ociConfigPath := flags.String("oci-config-file", "", "OCI CLI config file for generated commands; defaults from current oci-context")
	region := flags.String("region", "", "OCI region for generated commands; defaults from current oci-context")
	useOCIContext := flags.Bool("oci-context", true, "read current oci-context and token-service defaults for omitted values")
	ociContextBin := flags.String("oci-context-bin", "oci-context", "oci-context binary used for defaults")
	ociContextService := flags.String("oci-context-service", "", "oci-context token service used for issuer/scope defaults; defaults to current_service")
	var output string
	addOutputFlags(flags, &output, "json", "output format: json, yaml, plan, or text")

	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() > 0 {
		return fmt.Errorf("unexpected argument %q", flags.Arg(0))
	}
	if strings.TrimSpace(*name) == "" {
		return fmt.Errorf("--name is required")
	}
	include, err := includeForFlow(*flow)
	if err != nil {
		return err
	}
	clientType, err := planner.ParseClientType(*userClientType)
	if err != nil {
		return err
	}
	parsedPrincipalMode, err := planner.ParsePrincipalMode(*principalMode)
	if err != nil {
		return err
	}
	grants, err := planner.ParseAppRoleGrants(*appRoleGrants)
	if err != nil {
		return err
	}
	presets, err := planner.ParseRolePresets(*rolePreset)
	if err != nil {
		return err
	}

	visited := collectVisitedFlags(flags)
	contextName := ""
	defaults := ociContextDefaults{}
	if *useOCIContext {
		serviceName := firstNonEmpty(*ociContextService, defaultOCIContextServiceName(*service))
		defaults = loadOCIContextDefaults(*ociContextBin, serviceName)
		contextName = defaults.ContextName
		if !explicitFlags(visited, "issuer") && strings.TrimSpace(*issuer) == "" {
			*issuer = defaults.Issuer
		}
		if !explicitFlags(visited, "scope") && strings.TrimSpace(*scope) == "" {
			*scope = defaults.Scope
		}
		if !explicitFlags(visited, "service") && strings.TrimSpace(*service) == "" {
			*service = string(inferServiceKind(defaults, planner.ServiceGeneric))
		}
		if !explicitFlags(visited, "platform") && strings.TrimSpace(*platform) == "" && planner.ServiceKind(*service) == planner.ServiceOBP {
			*platform = defaults.Scope
		}
		if !explicitFlags(visited, "profile") && strings.TrimSpace(*profile) == "" {
			*profile = defaults.Profile
		}
		if !explicitFlags(visited, "oci-config-file") && strings.TrimSpace(*ociConfigPath) == "" {
			*ociConfigPath = defaults.OCIConfigPath
		}
		if !explicitFlags(visited, "region") && strings.TrimSpace(*region) == "" {
			*region = defaults.Region
		}
	}
	kind := include[0]
	plan, err := planner.Build(planner.Options{
		Service:              planner.ServiceKind(*service),
		Platform:             *platform,
		Issuer:               *issuer,
		Scope:                *scope,
		IDCSEndpoint:         *idcsEndpoint,
		ResourceAppID:        *resourceAppID,
		BaseAppName:          *baseAppName,
		BaseAppDisplayName:   *baseAppDisplayName,
		RedirectURL:          *redirectURL,
		Include:              include,
		UserClientType:       clientType,
		PrincipalMode:        parsedPrincipalMode,
		PrincipalEmailDomain: *principalEmailDomain,
		RolePresets:          presets,
		AppRoleGrants:        grants,
		OCIContext:           contextName,
		OCIProfile:           *profile,
		OCIConfigPath:        *ociConfigPath,
		OCIRegion:            *region,
		TokenServiceName:     *name,
		AppNames:             map[planner.AppKind]string{kind: *name},
	})
	if err != nil {
		return err
	}
	ociContext := handoff.ForOCIContext(plan)
	switch strings.ToLower(strings.TrimSpace(output)) {
	case "json", "oci-context-json", "context-json":
		data, err := handoff.JSON(ociContext)
		if err != nil {
			return err
		}
		_, err = stdout.Write(data)
		return err
	case "yaml", "yml", "oci-context-yaml", "token-services-yaml":
		fmt.Fprint(stdout, handoff.TokenServicesYAML(ociContext))
		return nil
	case "plan":
		encoder := json.NewEncoder(stdout)
		encoder.SetIndent("", "  ")
		return encoder.Encode(plan)
	case "text":
		writeTextPlan(stdout, plan)
		return nil
	default:
		return fmt.Errorf("unsupported output %q", output)
	}
}

func includeForFlow(flow string) ([]planner.AppKind, error) {
	switch strings.ToLower(strings.TrimSpace(flow)) {
	case "", "authorization-code", "auth-code", "user":
		return []planner.AppKind{planner.AppUser}, nil
	case "client-credentials", "service":
		return []planner.AppKind{planner.AppService}, nil
	case "jwt-client-credentials", "jwt-service", "service-jwt":
		return []planner.AppKind{planner.AppJWTService}, nil
	case "jwt-bearer", "jwt-user", "user-jwt":
		return []planner.AppKind{planner.AppJWTUser}, nil
	case "token-exchange", "workload", "workload-federation":
		return []planner.AppKind{planner.AppWorkload}, nil
	default:
		return nil, fmt.Errorf("unsupported flow %q", flow)
	}
}

func printPlanOutput(stdout io.Writer, plan planner.Plan, output string, tokenService string) error {
	ociContext := handoff.ForOCIContext(plan)
	switch strings.ToLower(strings.TrimSpace(output)) {
	case "json":
		encoder := json.NewEncoder(stdout)
		encoder.SetIndent("", "  ")
		return encoder.Encode(plan)
	case "text":
		writeTextPlan(stdout, plan)
		return nil
	case "oci-context-json", "context-json":
		data, err := handoff.JSON(ociContext)
		if err != nil {
			return err
		}
		_, err = stdout.Write(data)
		return err
	case "oci-context-yaml", "token-services-yaml":
		fmt.Fprint(stdout, handoff.TokenServicesYAML(ociContext))
		return nil
	case "oci-context-commands", "commands", "sh", "shell":
		fmt.Fprint(stdout, handoff.TokenCommandsScript(ociContext))
		return nil
	case "ochain-env":
		env, err := handoff.OChainEnv(ociContext, tokenService)
		if err != nil {
			return err
		}
		fmt.Fprint(stdout, env)
		return nil
	case "ochain-dotenv":
		env, err := handoff.OChainDotenv(ociContext, tokenService)
		if err != nil {
			return err
		}
		fmt.Fprint(stdout, env)
		return nil
	case "ochain-json":
		data, err := handoff.OChainJSON(ociContext, tokenService)
		if err != nil {
			return err
		}
		_, err = stdout.Write(data)
		return err
	default:
		return fmt.Errorf("unsupported output %q", output)
	}
}

func runApply(args []string, stdout io.Writer) error {
	flags := flag.NewFlagSet("apply", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	var planPath string
	addFileFlags(flags, &planPath, "path to a JSON plan emitted by oci-idm plan, or - for stdin")
	outDir := flags.String("out", "", "directory for generated apply artifacts")
	flags.Bool("execute", false, "deprecated compatibility flag; use --apply")
	apply := flags.Bool("apply", false, "apply OCI changes")
	confirm := flags.Bool("confirm", false, "deprecated alias for --apply")
	var output string
	addOutputFlags(flags, &output, "text", "output format: text or json")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() > 0 {
		return fmt.Errorf("unexpected argument %q", flags.Arg(0))
	}
	if strings.TrimSpace(planPath) == "" {
		return fmt.Errorf("-f/--file is required")
	}
	if !*apply && !*confirm {
		return fmt.Errorf("--apply is required to apply changes; use materialize plan for local review artifacts")
	}
	plan, err := readPlanFile(planPath)
	if err != nil {
		return err
	}
	result, err := applyexec.Execute(plan, *outDir, applyexec.Runner(runCommand))
	if err != nil {
		return err
	}
	return printApplyResult(stdout, result, output)
}

func runDiscover(args []string, stdout io.Writer) error {
	flags := flag.NewFlagSet("discover", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	issuer := flags.String("issuer", "", "OCI Identity Domains issuer URL")
	idcsEndpoint := flags.String("idcs-endpoint", "", "OCI Identity Domains base endpoint")
	query := flags.String("query", "", "service/app search text")
	appID := flags.String("app-id", "", "service/resource app id to inspect")
	profile := flags.String("profile", "", "optional OCI CLI profile to include in generated commands; defaults from current oci-context")
	ociConfigPath := flags.String("oci-config-file", "", "OCI CLI config file to include in generated commands; defaults from current oci-context")
	region := flags.String("region", "", "OCI region to include in generated commands; defaults from current oci-context")
	useOCIContext := flags.Bool("oci-context", true, "read current oci-context defaults for omitted values")
	ociContextBin := flags.String("oci-context-bin", "oci-context", "oci-context binary used for defaults")
	ociContextService := flags.String("oci-context-service", string(planner.ServiceOBP), "oci-context token service used for issuer defaults")
	var output string
	addOutputFlags(flags, &output, "json", "output format: json or text")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() > 0 {
		return fmt.Errorf("unexpected argument %q", flags.Arg(0))
	}
	visited := collectVisitedFlags(flags)
	if *useOCIContext {
		defaults := loadOCIContextDefaults(*ociContextBin, *ociContextService)
		if !explicitFlags(visited, "issuer") && strings.TrimSpace(*issuer) == "" {
			*issuer = defaults.Issuer
		}
		if !explicitFlags(visited, "profile") && strings.TrimSpace(*profile) == "" {
			*profile = defaults.Profile
		}
		if !explicitFlags(visited, "oci-config-file") && strings.TrimSpace(*ociConfigPath) == "" {
			*ociConfigPath = defaults.OCIConfigPath
		}
		if !explicitFlags(visited, "region") && strings.TrimSpace(*region) == "" {
			*region = defaults.Region
		}
	}
	plan, err := discovery.Build(discovery.Options{
		Issuer:        *issuer,
		IDCSEndpoint:  *idcsEndpoint,
		Query:         *query,
		AppID:         *appID,
		Profile:       *profile,
		OCIConfigPath: *ociConfigPath,
		Region:        *region,
	})
	if err != nil {
		return err
	}
	switch strings.ToLower(strings.TrimSpace(output)) {
	case "json":
		encoder := json.NewEncoder(stdout)
		encoder.SetIndent("", "  ")
		return encoder.Encode(plan)
	case "text":
		fmt.Fprintf(stdout, "idcsEndpoint: %s\n", plan.IDCSEndpoint)
		for _, command := range plan.Commands {
			fmt.Fprintf(stdout, "%s: %s\n  %s\n", command.Key, command.Description, command.Command)
		}
		return nil
	default:
		return fmt.Errorf("unsupported output %q", output)
	}
}

type appPatchPlan struct {
	SchemaVersion        string              `json:"schemaVersion"`
	AppID                string              `json:"appId"`
	IDCSEndpoint         string              `json:"idcsEndpoint"`
	AllowOffline         bool                `json:"allowOffline,omitempty"`
	AddRedirectURIs      []string            `json:"addRedirectUris,omitempty"`
	AddGrants            []string            `json:"addGrants,omitempty"`
	CurrentAllowOffline  *bool               `json:"currentAllowOffline,omitempty"`
	CurrentRedirectURIs  []string            `json:"currentRedirectUris,omitempty"`
	CurrentAllowedGrants []string            `json:"currentAllowedGrants,omitempty"`
	Operations           []appPatchOperation `json:"operations,omitempty"`
	Status               string              `json:"status"`
	Command              string              `json:"command,omitempty"`
	Args                 []string            `json:"args,omitempty"`
	Executed             bool                `json:"executed"`
}

type appPatchState struct {
	ID                 string   `json:"id"`
	Name               string   `json:"name"`
	IsOPCService       bool     `json:"is-opc-service"`
	AllowOffline       bool     `json:"allow-offline"`
	RedirectURIs       []string `json:"redirect-uris"`
	AllowedGrants      []string `json:"allowed-grants"`
	ServiceTypeURN     string   `json:"service-type-urn"`
	EditableAttributes []struct {
		Name string `json:"name"`
	} `json:"editable-attributes"`
}

type appPatchOperation struct {
	Op    string `json:"op"`
	Path  string `json:"path"`
	Value any    `json:"value"`
}

type stringList []string

func (values *stringList) String() string { return strings.Join(*values, ",") }

func (values *stringList) Set(value string) error {
	value = strings.TrimSpace(value)
	if value == "" {
		return fmt.Errorf("value cannot be empty")
	}
	*values = append(*values, value)
	return nil
}

func runPatchApp(args []string, stdout io.Writer) error {
	flags := flag.NewFlagSet("patch app", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	appID := flags.String("app-id", "", "Identity Domains app id")
	issuer := flags.String("issuer", "", "OCI Identity Domains issuer URL")
	idcsEndpoint := flags.String("idcs-endpoint", "", "OCI Identity Domains base endpoint")
	allowOffline := flags.Bool("allow-offline", false, "allow the resource app to issue refresh tokens")
	var addRedirectURIs stringList
	var addGrants stringList
	flags.Var(&addRedirectURIs, "add-redirect-uri", "redirect URI to add; repeat for multiple values")
	flags.Var(&addGrants, "add-grant", "OAuth grant type to add; repeat for multiple values")
	profile := flags.String("profile", "", "OCI CLI profile; defaults from current oci-context")
	ociConfigPath := flags.String("oci-config-file", "", "OCI CLI config file; defaults from current oci-context")
	region := flags.String("region", "", "OCI region; defaults from current oci-context")
	useOCIContext := flags.Bool("oci-context", true, "read current oci-context defaults for omitted values")
	ociContextBin := flags.String("oci-context-bin", "oci-context", "oci-context binary used for defaults")
	ociContextService := flags.String("oci-context-service", string(planner.ServiceOBP), "oci-context token service used for issuer defaults")
	execute := flags.Bool("execute", false, "deprecated compatibility flag; use --apply")
	apply := flags.Bool("apply", false, "apply the patch after preview")
	confirm := flags.Bool("confirm", false, "deprecated alias for --apply")
	preflight := flags.Bool("preflight", true, "read app state, calculate missing values, and verify the result")
	var output string
	addOutputFlags(flags, &output, "json", "output format: json or text")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() > 0 {
		return fmt.Errorf("unexpected argument %q", flags.Arg(0))
	}
	visited := collectVisitedFlags(flags)
	if strings.TrimSpace(*appID) == "" {
		return fmt.Errorf("--app-id is required")
	}
	if (!visited["allow-offline"] || !*allowOffline) && len(addRedirectURIs) == 0 && len(addGrants) == 0 {
		return fmt.Errorf("set --allow-offline, --add-redirect-uri, or --add-grant")
	}
	if !*preflight {
		return fmt.Errorf("--preflight=false is not supported; patch app always reads and verifies live state")
	}
	if *useOCIContext {
		defaults := loadOCIContextDefaults(*ociContextBin, *ociContextService)
		if !explicitFlags(visited, "issuer") && strings.TrimSpace(*issuer) == "" {
			*issuer = defaults.Issuer
		}
		if !explicitFlags(visited, "profile") && strings.TrimSpace(*profile) == "" {
			*profile = defaults.Profile
		}
		if !explicitFlags(visited, "oci-config-file") && strings.TrimSpace(*ociConfigPath) == "" {
			*ociConfigPath = defaults.OCIConfigPath
		}
		if !explicitFlags(visited, "region") && strings.TrimSpace(*region) == "" {
			*region = defaults.Region
		}
	}
	endpoint := firstNonEmpty(*idcsEndpoint, *issuer)
	if strings.TrimSpace(endpoint) == "" {
		return fmt.Errorf("--issuer or --idcs-endpoint is required")
	}
	endpoint = strings.TrimRight(endpoint, "/")
	plan := appPatchPlan{
		SchemaVersion:   "oci-idm.app-patch.v1",
		AppID:           *appID,
		IDCSEndpoint:    endpoint,
		AllowOffline:    visited["allow-offline"] && *allowOffline,
		AddRedirectURIs: uniqueStrings(addRedirectURIs),
		AddGrants:       uniqueStrings(addGrants),
		Status:          "planned",
	}
	state, err := getAppPatchState(endpoint, *appID, *profile, *ociConfigPath, *region)
	if err != nil {
		return fmt.Errorf("inspect app %s before patch: %w", *appID, err)
	}
	plan.CurrentAllowOffline = boolPtr(state.AllowOffline)
	plan.CurrentRedirectURIs = state.RedirectURIs
	plan.CurrentAllowedGrants = state.AllowedGrants
	plan.Operations = appPatchOperations(state, plan)
	if len(plan.Operations) == 0 {
		plan.Status = "already-configured"
		return writeAppPatchPlan(stdout, output, plan)
	}
	if state.IsOPCService {
		for _, operation := range plan.Operations {
			if !appAttributeEditable(state, operation.Path) {
				return fmt.Errorf("app %s (%s) is an Oracle service app (%s) that protects %s; ask the Oracle service owner or support", firstNonEmpty(state.ID, *appID), firstNonEmpty(state.Name, "unknown"), firstNonEmpty(state.ServiceTypeURN, "unknown service"), operation.Path)
			}
		}
	}
	if *execute && !*apply && !*confirm {
		return fmt.Errorf("--execute requires --apply")
	}
	if !*apply && !*confirm {
		return writeAppPatchPlan(stdout, output, plan)
	}
	operations, err := json.Marshal(plan.Operations)
	if err != nil {
		return err
	}
	commandArgs := []string{"identity-domains", "app", "patch", "--endpoint", endpoint, "--app-id", *appID, "--schemas", `["urn:ietf:params:scim:api:messages:2.0:PatchOp"]`, "--operations", string(operations)}
	if strings.TrimSpace(*profile) != "" {
		commandArgs = append(commandArgs, "--profile", *profile)
	}
	if strings.TrimSpace(*ociConfigPath) != "" {
		commandArgs = append(commandArgs, "--config-file", *ociConfigPath)
	}
	if strings.TrimSpace(*region) != "" {
		commandArgs = append(commandArgs, "--region", *region)
	}
	plan.Command, plan.Args = "oci", commandArgs
	if _, err := runCommand("oci", commandArgs...); err != nil {
		return fmt.Errorf("patch app %s: %w", *appID, err)
	}
	plan.Executed, plan.Status = true, "updated"
	state, err = getAppPatchState(endpoint, *appID, *profile, *ociConfigPath, *region)
	if err != nil {
		return fmt.Errorf("verify app %s after patch: %w", *appID, err)
	}
	plan.CurrentAllowOffline = boolPtr(state.AllowOffline)
	plan.CurrentRedirectURIs, plan.CurrentAllowedGrants = state.RedirectURIs, state.AllowedGrants
	if len(appPatchOperations(state, plan)) != 0 {
		return fmt.Errorf("patch app %s completed but requested values are still missing", *appID)
	}
	return writeAppPatchPlan(stdout, output, plan)
}

func appPatchOperations(state appPatchState, plan appPatchPlan) []appPatchOperation {
	operations := []appPatchOperation{}
	if plan.AllowOffline && !state.AllowOffline {
		operations = append(operations, appPatchOperation{Op: "replace", Path: "allowOffline", Value: true})
	}
	if missing := missingStrings(plan.AddRedirectURIs, state.RedirectURIs); len(missing) > 0 {
		operations = append(operations, appPatchOperation{Op: "add", Path: "redirectUris", Value: missing})
	}
	if missing := missingStrings(plan.AddGrants, state.AllowedGrants); len(missing) > 0 {
		operations = append(operations, appPatchOperation{Op: "add", Path: "allowedGrants", Value: missing})
	}
	return operations
}

func uniqueStrings(values []string) []string { return missingStrings(values, nil) }

func missingStrings(want []string, have []string) []string {
	seen := map[string]bool{}
	for _, value := range have {
		seen[value] = true
	}
	missing := []string{}
	for _, value := range want {
		if !seen[value] {
			seen[value] = true
			missing = append(missing, value)
		}
	}
	return missing
}

func getAppPatchState(endpoint string, appID string, profile string, ociConfigPath string, region string) (appPatchState, error) {
	args := []string{
		"identity-domains", "app", "get",
		"--endpoint", endpoint,
		"--app-id", appID,
		"--attributes", "id,name,isOPCService,allowOffline,redirectUris,allowedGrants,editableAttributes,serviceTypeURN",
	}
	if strings.TrimSpace(profile) != "" {
		args = append(args, "--profile", profile)
	}
	if strings.TrimSpace(ociConfigPath) != "" {
		args = append(args, "--config-file", ociConfigPath)
	}
	if strings.TrimSpace(region) != "" {
		args = append(args, "--region", region)
	}
	data, err := runCommand("oci", args...)
	if err != nil {
		return appPatchState{}, err
	}
	var response struct {
		Data appPatchState `json:"data"`
	}
	if err := json.Unmarshal(data, &response); err != nil {
		return appPatchState{}, fmt.Errorf("decode OCI app response: %w", err)
	}
	return response.Data, nil
}

func appAttributeEditable(state appPatchState, name string) bool {
	for _, attribute := range state.EditableAttributes {
		if strings.EqualFold(strings.TrimSpace(attribute.Name), strings.TrimSpace(name)) {
			return true
		}
	}
	return false
}

func boolPtr(value bool) *bool {
	return &value
}

func writeAppPatchPlan(stdout io.Writer, output string, plan appPatchPlan) error {
	switch strings.ToLower(strings.TrimSpace(output)) {
	case "json":
		encoder := json.NewEncoder(stdout)
		encoder.SetIndent("", "  ")
		return encoder.Encode(plan)
	case "text":
		fmt.Fprintf(stdout, "appId: %s\nstatus: %s\nexecuted: %t\n", plan.AppID, plan.Status, plan.Executed)
		if plan.Command != "" {
			fmt.Fprintf(stdout, "command: %s %s\n", plan.Command, strings.Join(plan.Args, " "))
		}
		return nil
	default:
		return fmt.Errorf("unsupported output %q", output)
	}
}

type appRoleAssignment struct {
	SchemaVersion  string `json:"schemaVersion"`
	AppID          string `json:"appId"`
	RoleID         string `json:"roleId"`
	PrincipalType  string `json:"principalType"`
	PrincipalID    string `json:"principalId"`
	GrantMechanism string `json:"grantMechanism"`
	Status         string `json:"status"`
	Executed       bool   `json:"executed"`
}

func runAssignAppRole(args []string, stdout io.Writer) error {
	flags := flag.NewFlagSet("assign app-role", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	appID := flags.String("app-id", "", "Identity Domains resource app id")
	roleID := flags.String("role-id", "", "Identity Domains app-role id")
	userID := flags.String("user-id", "", "Identity Domains user id")
	groupID := flags.String("group-id", "", "Identity Domains group id")
	currentUser := flags.Bool("current-user", false, "resolve the current oci-context token subject to an Identity Domains user")
	flags.BoolVar(currentUser, "me", false, "alias for --current-user")
	issuer := flags.String("issuer", "", "OCI Identity Domains issuer URL")
	idcsEndpoint := flags.String("idcs-endpoint", "", "OCI Identity Domains base endpoint")
	profile := flags.String("profile", "", "OCI CLI profile; defaults from current oci-context")
	ociConfigPath := flags.String("oci-config-file", "", "OCI CLI config file; defaults from current oci-context")
	region := flags.String("region", "", "OCI region; defaults from current oci-context")
	useOCIContext := flags.Bool("oci-context", true, "read current oci-context defaults for omitted values")
	ociContextBin := flags.String("oci-context-bin", "oci-context", "oci-context binary used for defaults")
	ociContextService := flags.String("oci-context-service", string(planner.ServiceOBP), "oci-context token service used for issuer defaults")
	apply := flags.Bool("apply", false, "create the app-role assignment after preview")
	confirm := flags.Bool("confirm", false, "deprecated alias for --apply")
	var output string
	addOutputFlags(flags, &output, "json", "output format: json or text")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() > 0 {
		return fmt.Errorf("unexpected argument %q", flags.Arg(0))
	}
	if strings.TrimSpace(*appID) == "" || strings.TrimSpace(*roleID) == "" {
		return fmt.Errorf("--app-id and --role-id are required")
	}
	principalCount := 0
	if strings.TrimSpace(*userID) != "" {
		principalCount++
	}
	if strings.TrimSpace(*groupID) != "" {
		principalCount++
	}
	if *currentUser {
		principalCount++
	}
	if principalCount != 1 {
		return fmt.Errorf("set exactly one of --user-id, --group-id, or --current-user")
	}
	visited := collectVisitedFlags(flags)
	if *useOCIContext {
		defaults := loadOCIContextDefaults(*ociContextBin, *ociContextService)
		if !explicitFlags(visited, "issuer") && strings.TrimSpace(*issuer) == "" {
			*issuer = defaults.Issuer
		}
		if !explicitFlags(visited, "profile") && strings.TrimSpace(*profile) == "" {
			*profile = defaults.Profile
		}
		if !explicitFlags(visited, "oci-config-file") && strings.TrimSpace(*ociConfigPath) == "" {
			*ociConfigPath = defaults.OCIConfigPath
		}
		if !explicitFlags(visited, "region") && strings.TrimSpace(*region) == "" {
			*region = defaults.Region
		}
	}
	endpoint := strings.TrimRight(firstNonEmpty(*idcsEndpoint, *issuer), "/")
	if endpoint == "" {
		return fmt.Errorf("--issuer or --idcs-endpoint is required")
	}
	principalType, principalID, mechanism := "User", strings.TrimSpace(*userID), planner.AdministratorToUserGrant
	if strings.TrimSpace(*groupID) != "" {
		principalType, principalID, mechanism = "Group", strings.TrimSpace(*groupID), planner.AdministratorToGroupGrant
	}
	if *currentUser {
		resolvedUserID, err := currentIdentityDomainUserID(*ociContextBin, *ociContextService, endpoint, *profile, *ociConfigPath, *region)
		if err != nil {
			return err
		}
		principalID = resolvedUserID
	}
	assignment := appRoleAssignment{
		SchemaVersion: "oci-idm.app-role-assignment.v1", AppID: strings.TrimSpace(*appID), RoleID: strings.TrimSpace(*roleID),
		PrincipalType: principalType, PrincipalID: principalID, GrantMechanism: mechanism, Status: "planned",
	}
	if exists, err := appRoleGrantExists(endpoint, assignment, *profile, *ociConfigPath, *region); err != nil {
		return err
	} else if exists {
		assignment.Status = "already-assigned"
		return writeAppRoleAssignment(stdout, output, assignment)
	}
	if !*apply && !*confirm {
		return writeAppRoleAssignment(stdout, output, assignment)
	}
	payload := planner.GrantInput{
		Schemas: []string{planner.GrantSchema}, GrantMechanism: mechanism,
		App:         planner.ResourceRef{Value: assignment.AppID},
		Entitlement: planner.EntitlementRef{AttributeName: "appRoles", AttributeValue: assignment.RoleID},
		Grantee:     planner.ResourceRef{Value: assignment.PrincipalID, Type: assignment.PrincipalType},
	}
	appJSON, err := json.Marshal(payload.App)
	if err != nil {
		return err
	}
	entitlementJSON, err := json.Marshal(payload.Entitlement)
	if err != nil {
		return err
	}
	granteeJSON, err := json.Marshal(payload.Grantee)
	if err != nil {
		return err
	}
	commandArgs := []string{"identity-domains", "grant", "create", "--endpoint", endpoint, "--schemas", `["` + planner.GrantSchema + `"]`, "--grant-mechanism", mechanism, "--app", string(appJSON), "--entitlement", string(entitlementJSON), "--grantee", string(granteeJSON)}
	if strings.TrimSpace(*profile) != "" {
		commandArgs = append(commandArgs, "--profile", *profile)
	}
	if strings.TrimSpace(*ociConfigPath) != "" {
		commandArgs = append(commandArgs, "--config-file", *ociConfigPath)
	}
	if strings.TrimSpace(*region) != "" {
		commandArgs = append(commandArgs, "--region", *region)
	}
	if _, err := runCommand("oci", commandArgs...); err != nil {
		return fmt.Errorf("assign app role: %w", err)
	}
	if exists, err := appRoleGrantExists(endpoint, assignment, *profile, *ociConfigPath, *region); err != nil {
		return err
	} else if !exists {
		return fmt.Errorf("app-role assignment completed but could not be verified")
	}
	assignment.Status, assignment.Executed = "assigned", true
	return writeAppRoleAssignment(stdout, output, assignment)
}

func currentIdentityDomainUserID(ociContextBin string, service string, endpoint string, profile string, ociConfigPath string, region string) (string, error) {
	data, err := runCommand(ociContextBin, "auth", "subject", "--service", service, "--require-issuer", endpoint)
	if err != nil {
		return "", fmt.Errorf("read current oci-context subject: %w", err)
	}
	var subject struct {
		Issuer     string `json:"issuer"`
		Subject    string `json:"subject"`
		NotExpired bool   `json:"not_expired"`
	}
	if err := json.Unmarshal(data, &subject); err != nil {
		return "", fmt.Errorf("decode current oci-context subject: %w", err)
	}
	if !subject.NotExpired || strings.TrimRight(subject.Issuer, "/") != endpoint || strings.TrimSpace(subject.Subject) == "" {
		return "", fmt.Errorf("current oci-context subject is not valid for %s", endpoint)
	}
	args := []string{"identity-domains", "users", "search", "--endpoint", endpoint, "--schemas", `["urn:ietf:params:scim:api:messages:2.0:SearchRequest"]`, "--filter", `id eq "` + subject.Subject + `"`, "--attributes", `["id"]`, "--count", "2"}
	if strings.TrimSpace(profile) != "" {
		args = append(args, "--profile", profile)
	}
	if strings.TrimSpace(ociConfigPath) != "" {
		args = append(args, "--config-file", ociConfigPath)
	}
	if strings.TrimSpace(region) != "" {
		args = append(args, "--region", region)
	}
	data, err = runCommand("oci", args...)
	if err != nil {
		return "", fmt.Errorf("resolve current Identity Domains user: %w", err)
	}
	var response struct {
		Resources []struct {
			ID string `json:"id"`
		} `json:"Resources"`
	}
	if err := json.Unmarshal(data, &response); err != nil {
		return "", fmt.Errorf("decode current Identity Domains user: %w", err)
	}
	if len(response.Resources) != 1 || strings.TrimSpace(response.Resources[0].ID) == "" {
		return "", fmt.Errorf("current oci-context subject did not resolve to exactly one Identity Domains user")
	}
	return response.Resources[0].ID, nil
}

func appRoleGrantExists(endpoint string, assignment appRoleAssignment, profile string, ociConfigPath string, region string) (bool, error) {
	args := []string{"identity-domains", "grants", "search", "--endpoint", endpoint, "--schemas", `["urn:ietf:params:scim:api:messages:2.0:SearchRequest"]`, "--filter", `grantee.value eq "` + assignment.PrincipalID + `" and entitlement.attributeValue eq "` + assignment.RoleID + `" and app.value eq "` + assignment.AppID + `" and grantMechanism eq "` + assignment.GrantMechanism + `"`, "--attributes", `["id"]`, "--count", "1"}
	if strings.TrimSpace(profile) != "" {
		args = append(args, "--profile", profile)
	}
	if strings.TrimSpace(ociConfigPath) != "" {
		args = append(args, "--config-file", ociConfigPath)
	}
	if strings.TrimSpace(region) != "" {
		args = append(args, "--region", region)
	}
	data, err := runCommand("oci", args...)
	if err != nil {
		return false, fmt.Errorf("inspect app-role assignment: %w", err)
	}
	var response struct {
		Resources []struct {
			ID string `json:"id"`
		} `json:"Resources"`
	}
	if err := json.Unmarshal(data, &response); err != nil {
		return false, fmt.Errorf("decode app-role assignment search: %w", err)
	}
	return len(response.Resources) > 0 && strings.TrimSpace(response.Resources[0].ID) != "", nil
}

func writeAppRoleAssignment(stdout io.Writer, output string, assignment appRoleAssignment) error {
	switch strings.ToLower(strings.TrimSpace(output)) {
	case "json":
		encoder := json.NewEncoder(stdout)
		encoder.SetIndent("", "  ")
		return encoder.Encode(assignment)
	case "text":
		fmt.Fprintf(stdout, "appId: %s\nroleId: %s\nprincipal: %s %s\nstatus: %s\nexecuted: %t\n", assignment.AppID, assignment.RoleID, assignment.PrincipalType, assignment.PrincipalID, assignment.Status, assignment.Executed)
		return nil
	default:
		return fmt.Errorf("unsupported output %q", output)
	}
}

func runDiagnose(args []string, stdout io.Writer) error {
	flags := flag.NewFlagSet("diagnose", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	service := flags.String("service", "", "service preset: generic or obp; defaults from current oci-context else generic")
	issuer := flags.String("issuer", "", "OCI Identity Domains issuer URL")
	idcsEndpoint := flags.String("idcs-endpoint", "", "OCI Identity Domains base endpoint")
	resourceAppID := flags.String("resource-app-id", "", "target service/resource app id")
	candidateAppID := flags.String("candidate-app-id", "", "candidate OAuth client app id")
	knownGoodAppID := flags.String("known-good-app-id", "", "optional known-working OAuth client app id to compare")
	profile := flags.String("profile", "", "optional OCI CLI profile to include in generated commands; defaults from current oci-context")
	ociConfigPath := flags.String("oci-config-file", "", "OCI CLI config file to include in generated commands; defaults from current oci-context")
	region := flags.String("region", "", "OCI region to include in generated commands; defaults from current oci-context")
	useOCIContext := flags.Bool("oci-context", true, "read current oci-context and token-service defaults for omitted values")
	ociContextBin := flags.String("oci-context-bin", "oci-context", "oci-context binary used for defaults")
	ociContextService := flags.String("oci-context-service", "", "oci-context token service used for issuer defaults; defaults to --service for non-generic services")
	var output string
	addOutputFlags(flags, &output, "json", "output format: json or text")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() > 0 {
		return fmt.Errorf("unexpected argument %q", flags.Arg(0))
	}
	visited := collectVisitedFlags(flags)
	if *useOCIContext {
		serviceName := firstNonEmpty(*ociContextService, defaultOCIContextServiceName(*service))
		defaults := loadOCIContextDefaults(*ociContextBin, serviceName)
		if !explicitFlags(visited, "issuer") && strings.TrimSpace(*issuer) == "" {
			*issuer = defaults.Issuer
		}
		if !explicitFlags(visited, "service") && strings.TrimSpace(*service) == "" {
			*service = string(inferServiceKind(defaults, planner.ServiceGeneric))
		}
		if !explicitFlags(visited, "profile") && strings.TrimSpace(*profile) == "" {
			*profile = defaults.Profile
		}
		if !explicitFlags(visited, "oci-config-file") && strings.TrimSpace(*ociConfigPath) == "" {
			*ociConfigPath = defaults.OCIConfigPath
		}
		if !explicitFlags(visited, "region") && strings.TrimSpace(*region) == "" {
			*region = defaults.Region
		}
	}
	plan, err := diagnose.Build(diagnose.Options{
		Service:        diagnose.ServiceKind(*service),
		Issuer:         *issuer,
		IDCSEndpoint:   *idcsEndpoint,
		ResourceAppID:  *resourceAppID,
		CandidateAppID: *candidateAppID,
		KnownGoodAppID: *knownGoodAppID,
		Profile:        *profile,
		OCIConfigPath:  *ociConfigPath,
		Region:         *region,
	})
	if err != nil {
		return err
	}
	switch strings.ToLower(strings.TrimSpace(output)) {
	case "json":
		encoder := json.NewEncoder(stdout)
		encoder.SetIndent("", "  ")
		return encoder.Encode(plan)
	case "text":
		fmt.Fprintf(stdout, "idcsEndpoint: %s\n", plan.IDCSEndpoint)
		fmt.Fprintf(stdout, "resourceAppId: %s\n", plan.ResourceAppID)
		if plan.CandidateAppID != "" {
			fmt.Fprintf(stdout, "candidateAppId: %s\n", plan.CandidateAppID)
		}
		if plan.KnownGoodAppID != "" {
			fmt.Fprintf(stdout, "knownGoodAppId: %s\n", plan.KnownGoodAppID)
		}
		for _, command := range plan.Commands {
			fmt.Fprintf(stdout, "%s: %s\n  %s\n", command.Key, command.Description, command.Command)
		}
		for _, item := range plan.Interpretation {
			fmt.Fprintf(stdout, "note: %s\n", item)
		}
		return nil
	default:
		return fmt.Errorf("unsupported output %q", output)
	}
}

func runMaterialize(args []string, stdout io.Writer) error {
	flags := flag.NewFlagSet("materialize", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	var planPath string
	addFileFlags(flags, &planPath, "path to a JSON plan emitted by oci-idm plan")
	outDir := flags.String("out", "", "directory for payload JSON files and helper scripts")
	var output string
	addOutputFlags(flags, &output, "text", "output format: text or json")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() > 0 {
		return fmt.Errorf("unexpected argument %q", flags.Arg(0))
	}
	if strings.TrimSpace(planPath) == "" {
		return fmt.Errorf("-f/--file is required")
	}
	result, err := materialize.FromPlanFile(planPath, *outDir)
	if err != nil {
		return err
	}
	switch strings.ToLower(strings.TrimSpace(output)) {
	case "json":
		encoder := json.NewEncoder(stdout)
		encoder.SetIndent("", "  ")
		return encoder.Encode(result)
	case "text":
		fmt.Fprintf(stdout, "wrote %d files to %s\n", len(result.Files), result.OutDir)
		for _, file := range result.Files {
			fmt.Fprintf(stdout, "  %s\n", file)
		}
		return nil
	default:
		return fmt.Errorf("unsupported output %q", output)
	}
}

func runValidate(args []string, stdout io.Writer) error {
	flags := flag.NewFlagSet("validate", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	var planPath string
	addFileFlags(flags, &planPath, "path to a JSON plan emitted by oci-idm plan")
	var output string
	addOutputFlags(flags, &output, "json", "output format: json or text")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() > 0 {
		return fmt.Errorf("unexpected argument %q", flags.Arg(0))
	}
	if strings.TrimSpace(planPath) == "" {
		return fmt.Errorf("-f/--file is required")
	}
	report, err := validation.FromPlanFile(planPath)
	if err != nil {
		return err
	}
	switch strings.ToLower(strings.TrimSpace(output)) {
	case "json":
		encoder := json.NewEncoder(stdout)
		encoder.SetIndent("", "  ")
		return encoder.Encode(report)
	case "text":
		for _, check := range report.Checks {
			fmt.Fprintf(stdout, "%s: %s", check.Status, check.Key)
			if check.Message != "" {
				fmt.Fprintf(stdout, " - %s", check.Message)
			}
			fmt.Fprintln(stdout)
		}
		for _, command := range report.Commands {
			fmt.Fprintf(stdout, "manual: %s\n  %s\n", command.Key, command.Command)
		}
		return nil
	default:
		return fmt.Errorf("unsupported output %q", output)
	}
}

func runDoctor(args []string, stdout io.Writer) error {
	flags := flag.NewFlagSet("doctor", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	var planPath string
	addFileFlags(flags, &planPath, "optional JSON plan emitted by oci-idm plan, or - for stdin")
	service := flags.String("service", string(planner.ServiceOBP), "service preset used for token-service defaults")
	ociContextService := flags.String("oci-context-service", "", "oci-context token service name; defaults from --service")
	ociContextBin := flags.String("oci-context-bin", "oci-context", "oci-context binary used for defaults")
	var output string
	addOutputFlags(flags, &output, "json", "output format: json or text")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() > 0 {
		return fmt.Errorf("unexpected argument %q", flags.Arg(0))
	}
	defaults := resolvedDoctorDefaults(*ociContextBin, *service, *ociContextService)
	var report doctor.Report
	var err error
	if strings.TrimSpace(planPath) != "" {
		report, err = doctor.FromPlanFile(planPath, defaults)
	} else {
		report = doctor.FromDefaults(defaults)
	}
	if err != nil {
		return err
	}
	return printDoctorReport(stdout, report, output)
}

func runHandoff(args []string, stdout io.Writer) error {
	flags := flag.NewFlagSet("handoff", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	var planPath string
	addFileFlags(flags, &planPath, "path to a JSON plan emitted by oci-idm plan, or - for stdin")
	target := flags.String("target", "oci-context", "handoff target: oci-context or ochain")
	var output string
	addOutputFlags(flags, &output, "json", "output format: json, yaml, commands, env, or dotenv")
	importToOCIContext := flags.Bool("import", false, "preview generated token services with oci-context handoff accept")
	importDryRun := flags.Bool("dry-run", false, "alias for the default preview when using --import")
	importApply := flags.Bool("apply", false, "write and verify the reviewed oci-context handoff when using --import")
	outDir := flags.String("out", "", "directory for generated handoff artifacts when using --import")
	ociContextBin := flags.String("oci-context-bin", "oci-context", "oci-context binary used for --import")
	tokenService := flags.String("token-service", "", "token service name for OChain handoff output")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() > 0 {
		return fmt.Errorf("unexpected argument %q", flags.Arg(0))
	}
	if strings.TrimSpace(planPath) == "" {
		return fmt.Errorf("-f/--file is required")
	}
	normalizedTarget := strings.ToLower(strings.TrimSpace(*target))
	normalizedOutput := strings.ToLower(strings.TrimSpace(output))
	if normalizedTarget == "oci-context" && strings.HasPrefix(normalizedOutput, "ochain") {
		normalizedTarget = "ochain"
	}
	if normalizedTarget != "oci-context" && normalizedTarget != "ochain" {
		return fmt.Errorf("unsupported handoff target %q", *target)
	}
	if *importToOCIContext {
		if normalizedTarget != "oci-context" {
			return fmt.Errorf("--import only supports --target oci-context")
		}
		if *importDryRun && *importApply {
			return fmt.Errorf("--dry-run and --apply cannot be used together")
		}
		result, err := materialize.FromPlanFile(planPath, *outDir)
		if err != nil {
			return err
		}
		file := filepath.Join(result.OutDir, "oci-context-token-services.yml")
		args := []string{"handoff", "accept", "--file", file}
		if *importApply {
			args = append(args, "--apply")
		}
		out, err := runCommand(*ociContextBin, args...)
		if err != nil {
			return err
		}
		fmt.Fprint(stdout, string(out))
		return nil
	}
	plan, err := readPlanFile(planPath)
	if err != nil {
		return err
	}
	ociContext := handoff.ForOCIContext(plan)
	if normalizedTarget == "ochain" {
		return printOChainHandoff(stdout, ociContext, normalizedOutput, *tokenService)
	}
	switch normalizedOutput {
	case "json":
		data, err := handoff.JSON(ociContext)
		if err != nil {
			return err
		}
		_, err = stdout.Write(data)
		return err
	case "yaml", "yml":
		fmt.Fprint(stdout, handoff.TokenServicesYAML(ociContext))
		return nil
	case "commands", "sh", "shell":
		fmt.Fprint(stdout, handoff.TokenCommandsScript(ociContext))
		return nil
	default:
		return fmt.Errorf("unsupported output %q", output)
	}
}

func printOChainHandoff(stdout io.Writer, value handoff.OCIContext, output string, tokenService string) error {
	switch output {
	case "env", "sh", "shell", "export", "exports", "ochain-env", "ochain":
		env, err := handoff.OChainEnv(value, tokenService)
		if err != nil {
			return err
		}
		fmt.Fprint(stdout, env)
		return nil
	case "dotenv", "ochain-dotenv":
		env, err := handoff.OChainDotenv(value, tokenService)
		if err != nil {
			return err
		}
		fmt.Fprint(stdout, env)
		return nil
	case "json", "ochain-json":
		data, err := handoff.OChainJSON(value, tokenService)
		if err != nil {
			return err
		}
		_, err = stdout.Write(data)
		return err
	default:
		return fmt.Errorf("unsupported output %q for target ochain", output)
	}
}

func readPlanFile(path string) (planner.Plan, error) {
	var data []byte
	var err error
	if strings.TrimSpace(path) == "-" {
		data, err = io.ReadAll(stdinReader)
	} else {
		data, err = os.ReadFile(path)
	}
	if err != nil {
		return planner.Plan{}, err
	}
	var plan planner.Plan
	if err := json.Unmarshal(data, &plan); err != nil {
		return planner.Plan{}, err
	}
	return plan, nil
}

func writeRootHelp(stdout io.Writer, program string) {
	fmt.Fprintf(stdout, `%s plans OCI Identity Domains apps, grants, and token-helper handoffs.

Usage:
  %s get defaults [options]
  %s get domains [options]
  %s describe domain --domain-id domain-ocid
  %s plan domain --name example-domain --description '...' --license-type <type>
  %s create domain -f domain-plan.json [--apply]
  %s get services [options]
  %s get service-apps [options]
  %s describe service-app [options]
  %s clone app --flow authorization-code --name hebe-obp-user
  %s edit app --app-id resource-app-id --allow-offline [--apply]
  %s create app-role-assignment --app-id app-id --role-id role-id --group-id group-id [--apply]
  %s plan apps [options]
  %s export --shape obpee-cp [options]
  %s plan apps [options] -o oci-context-yaml
  %s plan apps [options] -o ochain-env
  %s diagnose apps [options]
  %s doctor plan -f plan.json
  %s materialize plan -f plan.json --out ./idcs-artifacts
  %s handoff -f plan.json --target oci-context -o yaml
  %s handoff -f plan.json --import --out ./idcs-artifacts [--apply]
  %s apply plan -f plan.json --apply
  %s validate plan -f plan.json
  %s version

Plan options:
  --service generic|obp
  --issuer https://idcs-example.identity.oraclecloud.com
  --scope https://service.example.com
  --platform https://service.example.com
  --resource-app-id target-service-app-id
  --role-preset obp-admin
  --app-role-grants ADMIN=app-role-id,REST_CLIENT=app-role-id
  --principal-mode auto|none|same-name-user
  --principal-email-domain example.invalid
  --include user,service,jwt
    jwt expands to jwt-service,jwt-user,workload
  clone app --flow authorization-code --name <app-name>
    emits one oci-context auth target; pipe to oci-context service add --set-current
  --oci-context=true
    read profile, region, config path, current_service, issuer, and scope defaults from current oci-context
  --oci-context-service obp
    token service name for issuer/scope defaults
  export --shape obpee-cp
    renders a secret-free Control Plane OIDC payload from --domain, --app, and --policy
  edit app
    preview --allow-offline, --add-redirect-uri, or --add-grant values; add --apply to write
  create app-role-assignment
    preview one User or Group app-role grant; add --apply to write; existing grants are retained
  -o, --output json|text|oci-context-yaml|oci-context-json|commands|ochain-env|ochain-dotenv|ochain-json

Pipe contracts:
  plan-consuming commands accept -f - for stdin
  clone app emits JSON that can pipe into oci-context service add --set-current
  plan apps -o oci-context-yaml can pipe into oci-context service add --set-current
  plan apps -o ochain-env emits OCHAIN_TOKEN_COMMAND
  handoff remains available for saved plan files
`, program, program, program, program, program, program, program, program, program, program, program, program, program, program, program, program, program, program, program, program, program, program, program, program)
}

func writeTextPlan(stdout io.Writer, plan planner.Plan) {
	fmt.Fprintf(stdout, "schema: %s\n", plan.SchemaVersion)
	fmt.Fprintf(stdout, "service: %s\n", plan.Target.Service)
	if plan.Target.OCIContext != "" {
		fmt.Fprintf(stdout, "ociContext: %s\n", plan.Target.OCIContext)
	}
	if plan.Target.OCIProfile != "" {
		fmt.Fprintf(stdout, "ociProfile: %s\n", plan.Target.OCIProfile)
	}
	fmt.Fprintf(stdout, "issuer: %s\n", plan.Target.Issuer)
	fmt.Fprintf(stdout, "scope: %s\n", plan.Target.Scope)
	fmt.Fprintf(stdout, "idcsEndpoint: %s\n", plan.Target.IDCSEndpoint)
	if plan.Target.ResourceAppID != "" {
		fmt.Fprintf(stdout, "resourceAppId: %s\n", plan.Target.ResourceAppID)
	}
	fmt.Fprintf(stdout, "redirectUrl: %s\n", plan.Target.RedirectURL)
	fmt.Fprintln(stdout, "apps:")
	for _, app := range plan.Apps {
		fmt.Fprintf(stdout, "  - %s: %s grants %s\n", app.Name, app.ClientType, strings.Join(app.AllowedGrants, ", "))
		for _, action := range app.OCIPreCreate {
			fmt.Fprintf(stdout, "    pre-create: %s\n", action.Command)
		}
		fmt.Fprintf(stdout, "    create: %s\n", app.OCICreateCommand)
		for _, action := range app.OCIPostCreate {
			fmt.Fprintf(stdout, "    post-create: %s\n", action.Command)
		}
	}
}

func collectVisitedFlags(flags *flag.FlagSet) map[string]bool {
	visited := map[string]bool{}
	flags.Visit(func(f *flag.Flag) {
		visited[f.Name] = true
	})
	return visited
}

func defaultOCIContextServiceName(service string) string {
	switch strings.ToLower(strings.TrimSpace(service)) {
	case string(planner.ServiceOBP):
		return string(planner.ServiceOBP)
	default:
		return ""
	}
}

func inferServiceKind(defaults ociContextDefaults, fallback planner.ServiceKind) planner.ServiceKind {
	serviceName := strings.ToLower(strings.TrimSpace(defaults.ServiceName))
	scope := strings.ToLower(strings.TrimSpace(defaults.Scope))
	if serviceName == string(planner.ServiceOBP) || strings.Contains(serviceName, "obp") || strings.Contains(scope, "/restproxy") || strings.Contains(scope, "blockchain.ocp.oraclecloud.com") {
		return planner.ServiceOBP
	}
	if fallback == "" {
		return planner.ServiceGeneric
	}
	return fallback
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			return trimmed
		}
	}
	return ""
}

func resolvedDoctorDefaults(bin string, service string, serviceOverride string) doctor.Defaults {
	requestedService := firstNonEmpty(serviceOverride, defaultOCIContextServiceName(service), service)
	serviceName := requestedService
	defaults := loadOCIContextDefaults(bin, serviceName)
	serviceName = firstNonEmpty(defaults.ServiceName, serviceName)
	if serviceName == "" {
		fallback := loadOCIContextDefaults(bin, string(planner.ServiceOBP))
		if fallback.Issuer != "" || fallback.Scope != "" {
			defaults = fallback
			serviceName = firstNonEmpty(fallback.ServiceName, string(planner.ServiceOBP))
		} else {
			serviceName = string(planner.ServiceOBP)
		}
	}
	return doctor.Defaults{
		ContextName:   defaults.ContextName,
		Profile:       defaults.Profile,
		Region:        defaults.Region,
		OCIConfigPath: defaults.OCIConfigPath,
		ServiceName:   serviceName,
		Issuer:        defaults.Issuer,
		Scope:         defaults.Scope,
	}
}

func printDefaults(stdout io.Writer, defaults doctor.Defaults, output string) error {
	switch strings.ToLower(strings.TrimSpace(output)) {
	case "json":
		encoder := json.NewEncoder(stdout)
		encoder.SetIndent("", "  ")
		return encoder.Encode(defaults)
	case "text":
		fmt.Fprintf(stdout, "context: %s\n", defaults.ContextName)
		fmt.Fprintf(stdout, "profile: %s\n", defaults.Profile)
		fmt.Fprintf(stdout, "region: %s\n", defaults.Region)
		fmt.Fprintf(stdout, "ociConfigPath: %s\n", defaults.OCIConfigPath)
		fmt.Fprintf(stdout, "service: %s\n", defaults.ServiceName)
		fmt.Fprintf(stdout, "issuer: %s\n", defaults.Issuer)
		fmt.Fprintf(stdout, "scope: %s\n", defaults.Scope)
		return nil
	default:
		return fmt.Errorf("unsupported output %q", output)
	}
}

func printDoctorReport(stdout io.Writer, report doctor.Report, output string) error {
	switch strings.ToLower(strings.TrimSpace(output)) {
	case "json":
		encoder := json.NewEncoder(stdout)
		encoder.SetIndent("", "  ")
		return encoder.Encode(report)
	case "text":
		for _, check := range report.Checks {
			fmt.Fprintf(stdout, "%s: %s", check.Status, check.Key)
			if check.Message != "" {
				fmt.Fprintf(stdout, " - %s", check.Message)
			}
			fmt.Fprintln(stdout)
		}
		for _, command := range report.Commands {
			fmt.Fprintf(stdout, "manual: %s\n  %s\n", command.Key, command.Command)
		}
		return nil
	default:
		return fmt.Errorf("unsupported output %q", output)
	}
}

func printApplyResult(stdout io.Writer, result applyexec.Result, output string) error {
	switch strings.ToLower(strings.TrimSpace(output)) {
	case "json":
		encoder := json.NewEncoder(stdout)
		encoder.SetIndent("", "  ")
		return encoder.Encode(result)
	case "text":
		for _, step := range result.Steps {
			fmt.Fprintf(stdout, "%s: %s", step.Status, step.Key)
			if step.ID != "" {
				fmt.Fprintf(stdout, " id=%s", step.ID)
			}
			if step.Message != "" {
				fmt.Fprintf(stdout, " - %s", step.Message)
			}
			fmt.Fprintln(stdout)
		}
		return nil
	default:
		return fmt.Errorf("unsupported output %q", output)
	}
}
