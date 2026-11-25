// Package grouprules plans additive Identity Domains group memberships and a scoped access-token claim.
package grouprules

import (
	"fmt"
	"net/url"
	"slices"
	"strings"
)

const SchemaVersion = "oci-idm.group-rules-plan.v1"

type Template struct {
	Target Target  `json:"target"`
	Groups []Group `json:"groups"`
}

type Target struct {
	ConfigFile string `json:"ociConfigFile,omitempty"`
	Issuer     string `json:"issuer"`
	Scope      string `json:"resourceScope"`
	Profile    string `json:"ociProfile"`
	Region     string `json:"ociRegion,omitempty"`
}

type Group struct {
	Name  string   `json:"name"`
	Users []string `json:"users,omitempty"`
}

type Plan struct {
	SchemaVersion string `json:"schemaVersion"`
	Template
	Claim Claim `json:"claim"`
}

type Claim struct {
	Name       string   `json:"name"`
	Value      string   `json:"value"`
	Expression bool     `json:"expression"`
	Mode       string   `json:"mode"`
	TokenType  string   `json:"tokenType"`
	AllScopes  bool     `json:"allScopes"`
	Scopes     []string `json:"scopes"`
}

func scopedClaim(scope string) Claim {
	return Claim{Name: "group_roles", Value: "$user.groups.*.display", Expression: true, Mode: "always", TokenType: "AT", Scopes: []string{scope}}
}

func (c Claim) matches(expected Claim) bool {
	return c.Name == expected.Name && c.Value == expected.Value && c.Expression == expected.Expression && c.Mode == expected.Mode && c.TokenType == expected.TokenType && c.AllScopes == expected.AllScopes && slices.Equal(c.Scopes, expected.Scopes)
}

func Build(t Template) (Plan, error) {
	p := Plan{SchemaVersion: SchemaVersion, Template: t, Claim: scopedClaim(t.Target.Scope)}
	return p, p.Validate()
}

func (p Plan) Validate() error {
	if p.SchemaVersion != SchemaVersion {
		return fmt.Errorf("unsupported group-rules plan schema %q", p.SchemaVersion)
	}
	u, err := url.Parse(p.Target.Issuer)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" || u.ForceQuery {
		return fmt.Errorf("issuer must be an HTTPS domain origin")
	}
	if strings.TrimSpace(p.Target.Profile) == "" || strings.TrimSpace(p.Target.Scope) == "" {
		return fmt.Errorf("an explicit OCI profile and resource scope are required")
	}
	if !p.Claim.matches(scopedClaim(p.Target.Scope)) {
		return fmt.Errorf("claim must match the reviewed single-scope access-token group claim")
	}
	if len(p.Groups) == 0 {
		return fmt.Errorf("at least one group is required")
	}
	seen := map[string]bool{}
	for _, g := range p.Groups {
		if g.Name == "" || strings.TrimSpace(g.Name) != g.Name || seen[strings.ToLower(g.Name)] {
			return fmt.Errorf("blank, noncanonical or duplicate group name %q", g.Name)
		}
		seen[strings.ToLower(g.Name)] = true
		users := map[string]bool{}
		for _, u := range g.Users {
			if u == "" || strings.TrimSpace(u) != u || users[strings.ToLower(u)] {
				return fmt.Errorf("blank, noncanonical or duplicate user in group %q", g.Name)
			}
			users[strings.ToLower(u)] = true
		}
	}
	return nil
}
