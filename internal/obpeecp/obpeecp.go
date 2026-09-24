package obpeecp

import (
	"fmt"
	"net/url"
	"strings"
)

const SchemaVersion = "oci-idm.obpee-cp.v1"

type Policy struct {
	Provider      Provider   `json:"provider"`
	GroupMappings Mappings   `json:"groupMappings"`
	SecretRefs    SecretRefs `json:"secretRefs"`
}

type Provider struct {
	ProviderName     string `json:"providerName"`
	ProviderType     string `json:"providerType"`
	Scope            string `json:"scope"`
	ClientClaimName  string `json:"clientClaimName"`
	ClientClaimValue string `json:"clientClaimValue"`
	GroupsClaimName  string `json:"groupsClaimName"`
	UserClaimName    string `json:"userClaimName"`
}

type Mappings struct {
	BPMAdminGroup          string `json:"bpmAdminGroup"`
	WalletSuperAdminGroup  string `json:"walletSuperAdminGroup"`
	InstanceAdminGroup     string `json:"instanceAdminGroup"`
	InstanceOperatorGroup  string `json:"instanceOperatorGroup"`
	InstanceAPIClientGroup string `json:"instanceApiClientGroup"`
	WalletOrgAdminGroup    string `json:"walletOrgAdminGroup"`
	WalletOrgUserGroup     string `json:"walletOrgUserGroup"`
	DASuperAdminGroup      string `json:"daSuperAdminGroup"`
	DATokenAdminGroup      string `json:"daTokenAdminGroup"`
	DADeployerGroup        string `json:"daDeployerGroup"`
	DAApproverGroup        string `json:"daApproverGroup"`
}

type SecretRefs struct {
	ProviderClientSecret string `json:"providerClientSecret"`
}

type Discovery struct {
	Issuer                string `json:"issuer"`
	JWKSURI               string `json:"jwks_uri"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	EndSessionEndpoint    string `json:"end_session_endpoint,omitempty"`
}

type Input struct {
	Domain          string
	App             string
	ControlPlaneURL string
	RedirectURI     string
	Policy          Policy
	Discovery       Discovery
}

type Document struct {
	SchemaVersion  string     `json:"schemaVersion"`
	Target         Target     `json:"target"`
	IdentityDomain Domain     `json:"identityDomain"`
	Provider       Provider   `json:"provider"`
	GroupMappings  Mappings   `json:"groupMappings"`
	SecretRefs     SecretRefs `json:"secretRefs"`
	Request        Request    `json:"request"`
}

type Target struct {
	ControlPlaneURL string `json:"controlPlaneUrl"`
	RedirectURI     string `json:"redirectUri"`
}

type Domain struct {
	Issuer        string `json:"issuer"`
	WellKnownURI  string `json:"wellKnownUri"`
	ApplicationID string `json:"applicationId"`
}

type Request struct {
	ProviderWellKnownConfigURI string `json:"providerWellKnownConfigUri"`
	ProviderName               string `json:"providerName"`
	ProviderType               string `json:"providerType"`
	ProviderIssuerURL          string `json:"providerIssuerUrl"`
	ProviderJWKSURI            string `json:"providerJwksUri"`
	ProviderAuthEndpoint       string `json:"providerAuthEndpoint"`
	ProviderTokenEndpoint      string `json:"providerTokenEndpoint"`
	ProviderEndSessionEndpoint string `json:"providerEndSessionEndpoint,omitempty"`
	ProviderScope              string `json:"providerScope"`
	ProviderClientClaimName    string `json:"providerClientClaimName"`
	ProviderClientClaimValue   string `json:"providerClientClaimValue"`
	ProviderGroupsClaimName    string `json:"providerGroupsClaimName"`
	ProviderClientID           string `json:"providerClientId"`
	ProviderUserClaimName      string `json:"providerUserClaimName"`
}

func Build(input Input) (Document, error) {
	issuer, err := normalizeURL(input.Domain, "--domain")
	if err != nil {
		return Document{}, err
	}
	controlPlaneURL, err := normalizeURL(input.ControlPlaneURL, "--control-plane-url")
	if err != nil {
		return Document{}, err
	}
	redirectURI, err := normalizeURL(input.RedirectURI, "--redirect-uri")
	if err != nil {
		return Document{}, err
	}
	if strings.TrimSpace(input.App) == "" {
		return Document{}, fmt.Errorf("--app is required")
	}
	if discoveredIssuer, err := normalizeURL(input.Discovery.Issuer, "discovery issuer"); err != nil || discoveredIssuer != issuer {
		if err != nil {
			return Document{}, err
		}
		return Document{}, fmt.Errorf("discovery issuer %q does not match --domain %q", discoveredIssuer, issuer)
	}
	for label, value := range map[string]string{
		"discovery jwks_uri":               input.Discovery.JWKSURI,
		"discovery authorization_endpoint": input.Discovery.AuthorizationEndpoint,
		"discovery token_endpoint":         input.Discovery.TokenEndpoint,
		"providerName":                     input.Policy.Provider.ProviderName,
		"providerType":                     input.Policy.Provider.ProviderType,
		"scope":                            input.Policy.Provider.Scope,
		"clientClaimName":                  input.Policy.Provider.ClientClaimName,
		"clientClaimValue":                 input.Policy.Provider.ClientClaimValue,
		"groupsClaimName":                  input.Policy.Provider.GroupsClaimName,
		"userClaimName":                    input.Policy.Provider.UserClaimName,
		"providerClientSecret reference":   input.Policy.SecretRefs.ProviderClientSecret,
	} {
		if strings.TrimSpace(value) == "" {
			return Document{}, fmt.Errorf("%s is required", label)
		}
	}
	for label, value := range map[string]string{
		"bpmAdminGroup":          input.Policy.GroupMappings.BPMAdminGroup,
		"walletSuperAdminGroup":  input.Policy.GroupMappings.WalletSuperAdminGroup,
		"instanceAdminGroup":     input.Policy.GroupMappings.InstanceAdminGroup,
		"instanceOperatorGroup":  input.Policy.GroupMappings.InstanceOperatorGroup,
		"instanceApiClientGroup": input.Policy.GroupMappings.InstanceAPIClientGroup,
		"walletOrgAdminGroup":    input.Policy.GroupMappings.WalletOrgAdminGroup,
		"walletOrgUserGroup":     input.Policy.GroupMappings.WalletOrgUserGroup,
		"daSuperAdminGroup":      input.Policy.GroupMappings.DASuperAdminGroup,
		"daTokenAdminGroup":      input.Policy.GroupMappings.DATokenAdminGroup,
		"daDeployerGroup":        input.Policy.GroupMappings.DADeployerGroup,
		"daApproverGroup":        input.Policy.GroupMappings.DAApproverGroup,
	} {
		if strings.TrimSpace(value) == "" {
			return Document{}, fmt.Errorf("groupMappings.%s is required", label)
		}
	}
	if _, err := normalizeURL(input.Discovery.JWKSURI, "discovery jwks_uri"); err != nil {
		return Document{}, err
	}
	if _, err := normalizeURL(input.Discovery.AuthorizationEndpoint, "discovery authorization_endpoint"); err != nil {
		return Document{}, err
	}
	if _, err := normalizeURL(input.Discovery.TokenEndpoint, "discovery token_endpoint"); err != nil {
		return Document{}, err
	}
	if input.Discovery.EndSessionEndpoint != "" {
		if _, err := normalizeURL(input.Discovery.EndSessionEndpoint, "discovery end_session_endpoint"); err != nil {
			return Document{}, err
		}
	}
	wellKnownURI := issuer + "/.well-known/openid-configuration"
	return Document{
		SchemaVersion:  SchemaVersion,
		Target:         Target{ControlPlaneURL: controlPlaneURL, RedirectURI: redirectURI},
		IdentityDomain: Domain{Issuer: issuer, WellKnownURI: wellKnownURI, ApplicationID: strings.TrimSpace(input.App)},
		Provider:       input.Policy.Provider, GroupMappings: input.Policy.GroupMappings, SecretRefs: input.Policy.SecretRefs,
		Request: Request{
			ProviderWellKnownConfigURI: wellKnownURI,
			ProviderName:               input.Policy.Provider.ProviderName, ProviderType: input.Policy.Provider.ProviderType,
			ProviderIssuerURL: issuer, ProviderJWKSURI: input.Discovery.JWKSURI,
			ProviderAuthEndpoint: input.Discovery.AuthorizationEndpoint, ProviderTokenEndpoint: input.Discovery.TokenEndpoint,
			ProviderEndSessionEndpoint: input.Discovery.EndSessionEndpoint, ProviderScope: input.Policy.Provider.Scope,
			ProviderClientClaimName: input.Policy.Provider.ClientClaimName, ProviderClientClaimValue: input.Policy.Provider.ClientClaimValue,
			ProviderGroupsClaimName: input.Policy.Provider.GroupsClaimName, ProviderClientID: strings.TrimSpace(input.App),
			ProviderUserClaimName: input.Policy.Provider.UserClaimName,
		},
	}, nil
}

func WellKnownURI(domain string) (string, error) {
	issuer, err := normalizeURL(domain, "--domain")
	if err != nil {
		return "", err
	}
	return issuer + "/.well-known/openid-configuration", nil
}

func normalizeURL(value string, name string) (string, error) {
	parsed, err := url.Parse(strings.TrimSpace(value))
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", fmt.Errorf("%s must be an https URL without query or fragment", name)
	}
	return strings.TrimRight(parsed.String(), "/"), nil
}
