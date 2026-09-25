package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
)

const (
	appsPlanConfigAPIVersion = "oci-idm.oracle.com/v1"
	appsPlanConfigKind       = "IdentityDomainAppsPlanConfig"
)

type appsPlanConfig struct {
	APIVersion string             `json:"apiVersion"`
	Kind       string             `json:"kind"`
	Spec       appsPlanConfigSpec `json:"spec"`
}

type appsPlanConfigSpec struct {
	Service              string `json:"service"`
	Platform             string `json:"platform"`
	Issuer               string `json:"issuer"`
	Scope                string `json:"scope"`
	IDCSSEndpoint        string `json:"idcsEndpoint"`
	ResourceAppID        string `json:"resourceAppId"`
	AppPrefix            string `json:"appPrefix"`
	RedirectURL          string `json:"redirectUrl"`
	Include              string `json:"include"`
	UserClientType       string `json:"userClientType"`
	PrincipalMode        string `json:"principalMode"`
	PrincipalEmailDomain string `json:"principalEmailDomain"`
	RolePreset           string `json:"rolePreset"`
	AppRoleGrants        string `json:"appRoleGrants"`
	TokenService         string `json:"tokenService"`
}

type appsPlanFlagValues struct {
	Service              *string
	Platform             *string
	Issuer               *string
	Scope                *string
	IDCSEndpoint         *string
	ResourceAppID        *string
	AppPrefix            *string
	RedirectURL          *string
	Include              *string
	UserClientType       *string
	PrincipalMode        *string
	PrincipalEmailDomain *string
	RolePreset           *string
	AppRoleGrants        *string
	TokenService         *string
}

func (values appsPlanFlagValues) applyPreset(name string, visited map[string]bool, sources map[string]string) error {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "":
		return nil
	case "ocix-local":
		if !visited["include"] {
			*values.Include = "user"
			sources["include"] = "preset:ocix-local"
		}
		return nil
	default:
		return fmt.Errorf("unsupported apps plan preset %q", name)
	}
}

func (values appsPlanFlagValues) applyConfig(spec appsPlanConfigSpec, visited map[string]bool, sources map[string]string) {
	set := func(flag, field string, target *string, value string) {
		if !visited[flag] && strings.TrimSpace(value) != "" {
			*target = value
			sources[field] = "plan-config"
		}
	}
	set("service", "service", values.Service, spec.Service)
	set("platform", "platform", values.Platform, spec.Platform)
	set("issuer", "issuer", values.Issuer, spec.Issuer)
	set("scope", "scope", values.Scope, spec.Scope)
	set("idcs-endpoint", "idcsEndpoint", values.IDCSEndpoint, spec.IDCSSEndpoint)
	set("resource-app-id", "resourceAppId", values.ResourceAppID, spec.ResourceAppID)
	set("app-prefix", "appPrefix", values.AppPrefix, spec.AppPrefix)
	set("redirect-url", "redirectUrl", values.RedirectURL, spec.RedirectURL)
	set("include", "include", values.Include, spec.Include)
	set("user-client-type", "userClientType", values.UserClientType, spec.UserClientType)
	set("principal-mode", "principalMode", values.PrincipalMode, spec.PrincipalMode)
	set("principal-email-domain", "principalEmailDomain", values.PrincipalEmailDomain, spec.PrincipalEmailDomain)
	set("role-preset", "rolePreset", values.RolePreset, spec.RolePreset)
	set("app-role-grants", "appRoleGrants", values.AppRoleGrants, spec.AppRoleGrants)
	set("token-service", "tokenService", values.TokenService, spec.TokenService)
}

func markExplicitAppsPlanInputs(visited map[string]bool, sources map[string]string) {
	for flag, field := range map[string]string{
		"service": "service", "platform": "platform", "issuer": "issuer", "scope": "scope",
		"idcs-endpoint": "idcsEndpoint", "resource-app-id": "resourceAppId", "app-prefix": "appPrefix",
		"redirect-url": "redirectUrl", "include": "include", "user-client-type": "userClientType",
		"principal-mode": "principalMode", "principal-email-domain": "principalEmailDomain",
		"role-preset": "rolePreset", "app-role-grants": "appRoleGrants", "token-service": "tokenService",
	} {
		if visited[flag] {
			sources[field] = "flag"
		}
	}
}

func readAppsPlanConfig(path string) (appsPlanConfig, error) {
	if strings.TrimSpace(path) == "" {
		return appsPlanConfig{}, nil
	}
	if strings.TrimSpace(path) == "-" {
		return appsPlanConfig{}, fmt.Errorf("--plan-config must name a file; use plan stdin for a generated apps plan")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return appsPlanConfig{}, err
	}
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	var config appsPlanConfig
	if err := decoder.Decode(&config); err != nil {
		return appsPlanConfig{}, fmt.Errorf("decode apps plan config: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return appsPlanConfig{}, fmt.Errorf("decode apps plan config: expected one JSON object")
	}
	if config.APIVersion != appsPlanConfigAPIVersion {
		return appsPlanConfig{}, fmt.Errorf("unsupported apps plan config apiVersion %q", config.APIVersion)
	}
	if config.Kind != appsPlanConfigKind {
		return appsPlanConfig{}, fmt.Errorf("unsupported apps plan config kind %q", config.Kind)
	}
	return config, nil
}
