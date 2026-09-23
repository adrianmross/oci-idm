package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

type commandRunner func(name string, args ...string) ([]byte, error)

var runCommand commandRunner = func(name string, args ...string) ([]byte, error) {
	output, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		message := strings.TrimSpace(string(output))
		if message != "" {
			return output, fmt.Errorf("%w: %s", err, message)
		}
	}
	return output, err
}

type ociContextDefaults struct {
	ContextName     string
	Profile         string
	Region          string
	OCIConfigPath   string
	TenancyOCID     string
	CompartmentOCID string
	ServiceName     string
	Issuer          string
	Scope           string
}

type ociContextExport struct {
	Name                string `json:"name"`
	Profile             string `json:"profile"`
	Region              string `json:"region"`
	TenancyOCID         string `json:"tenancy_ocid"`
	CompartmentOCID     string `json:"compartment_ocid"`
	CurrentService      string `json:"current_service"`
	CamelCurrentService string `json:"currentService"`
}

type ociContextPaths struct {
	OCIConfigPath string `json:"oci_config_path"`
}

type ociContextTokenService struct {
	Name   string `json:"name"`
	Issuer string `json:"issuer"`
	Scope  string `json:"scope"`
}

func loadOCIContextDefaults(bin string, serviceName string) ociContextDefaults {
	bin = strings.TrimSpace(bin)
	if bin == "" {
		bin = "oci-context"
	}
	defaults := ociContextDefaults{}
	if data, err := runCommand(bin, "export", "-f", "json"); err == nil {
		var current ociContextExport
		if json.Unmarshal(data, &current) == nil {
			defaults.ContextName = strings.TrimSpace(current.Name)
			defaults.Profile = strings.TrimSpace(current.Profile)
			defaults.Region = strings.TrimSpace(current.Region)
			defaults.TenancyOCID = strings.TrimSpace(current.TenancyOCID)
			defaults.CompartmentOCID = strings.TrimSpace(current.CompartmentOCID)
			defaults.ServiceName = firstNonEmpty(current.CurrentService, current.CamelCurrentService)
		}
	}
	if data, err := runCommand(bin, "paths", "-o", "json"); err == nil {
		var paths ociContextPaths
		if json.Unmarshal(data, &paths) == nil {
			defaults.OCIConfigPath = strings.TrimSpace(paths.OCIConfigPath)
		}
	}
	serviceName = strings.TrimSpace(serviceName)
	if serviceName == "" {
		serviceName = defaults.ServiceName
	}
	defaults.ServiceName = serviceName
	if serviceName != "" {
		if data, err := runCommand(bin, "auth", "service", "list", "-o", "json"); err == nil {
			var services []ociContextTokenService
			if json.Unmarshal(data, &services) == nil {
				for _, service := range services {
					if service.Name == serviceName {
						defaults.Issuer = strings.TrimSpace(service.Issuer)
						defaults.Scope = strings.TrimSpace(service.Scope)
						break
					}
				}
			}
		}
	}
	// OCI CLI-style environment settings are deliberate one-shell overrides of
	// the selected context. Explicit command flags still win in each caller.
	defaults.Profile = firstNonEmpty(os.Getenv("OCI_CLI_PROFILE"), defaults.Profile)
	defaults.OCIConfigPath = firstNonEmpty(os.Getenv("OCI_CLI_CONFIG_FILE"), defaults.OCIConfigPath)
	defaults.Region = firstNonEmpty(os.Getenv("OCI_CLI_REGION"), os.Getenv("OCI_REGION"), defaults.Region)
	defaults.TenancyOCID = firstNonEmpty(os.Getenv("OCI_TENANCY_OCID"), defaults.TenancyOCID)
	defaults.CompartmentOCID = firstNonEmpty(os.Getenv("OCI_COMPARTMENT_OCID"), defaults.CompartmentOCID)
	return defaults
}

func explicitFlags(flags map[string]bool, names ...string) bool {
	for _, name := range names {
		if flags[name] {
			return true
		}
	}
	return false
}
