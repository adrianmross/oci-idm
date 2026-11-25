package grouprules

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
)

type Runner func(name string, args ...string) ([]byte, error)
type Step struct {
	Resource string `json:"resource"`
	Action   string `json:"action"`
}
type domain struct {
	target Target
	out    string
	run    Runner
}
type entry struct {
	Claim
	ID          string   `json:"id"`
	DisplayName string   `json:"displayName"`
	UserName    string   `json:"userName"`
	Members     []member `json:"members"`
}
type member struct {
	Value string `json:"value"`
	Type  string `json:"type,omitempty"`
}

func (d domain) request(method, path string, payload any) (json.RawMessage, error) {
	args := []string{"raw-request", "--target-uri", strings.TrimRight(d.target.Issuer, "/") + "/admin/v1/" + path, "--http-method", method, "--profile", d.target.Profile}
	if d.target.ConfigFile != "" {
		args = append(args, "--config-file", d.target.ConfigFile)
	}
	if d.target.Region != "" {
		args = append(args, "--region", d.target.Region)
	}
	if payload != nil {
		f, err := os.CreateTemp(d.out, "request-*.json")
		if err != nil {
			return nil, err
		}
		err = json.NewEncoder(f).Encode(payload)
		closeErr := f.Close()
		if err != nil {
			return nil, err
		}
		if closeErr != nil {
			return nil, closeErr
		}
		args = append(args, "--request-body", "file://"+f.Name())
	}
	raw, err := d.run("oci", args...)
	if err != nil {
		return nil, fmt.Errorf("OCI %s %s failed", method, strings.SplitN(path, "?", 2)[0])
	}
	var resp struct {
		Data   json.RawMessage `json:"data"`
		Status string          `json:"status"`
	}
	if err := json.Unmarshal(raw, &resp); err != nil {
		return nil, fmt.Errorf("invalid OCI response: %w", err)
	}
	status, _, _ := strings.Cut(resp.Status, " ")
	code, err := strconv.Atoi(status)
	if err != nil || code < 200 || code > 299 {
		return nil, fmt.Errorf("OCI request returned status %q", resp.Status)
	}
	return resp.Data, nil
}

func (d domain) lookup(collection, attr, name, attributes string) (*entry, error) {
	// SCIM filter string literals use JSON quoting; URL encoding is a separate layer.
	literal, _ := json.Marshal(name)
	query := url.Values{"filter": {attr + " eq " + string(literal)}, "attributes": {attributes}, "count": {"2"}}
	raw, err := d.request("GET", collection+"?"+query.Encode(), nil)
	if err != nil {
		return nil, err
	}
	var page struct {
		Resources []json.RawMessage `json:"Resources"`
		Total     *int              `json:"totalResults"`
	}
	if err := json.Unmarshal(raw, &page); err != nil {
		return nil, err
	}
	if page.Total == nil || *page.Total != len(page.Resources) || len(page.Resources) > 1 {
		return nil, fmt.Errorf("incomplete or ambiguous %s lookup for %q", collection, name)
	}
	if len(page.Resources) == 0 {
		return nil, nil
	}
	item := new(entry)
	if err := json.Unmarshal(page.Resources[0], item); err != nil {
		return nil, err
	}
	if collection == "CustomClaims" {
		var flags struct {
			AllScopes *bool `json:"allScopes"`
		}
		if err := json.Unmarshal(page.Resources[0], &flags); err != nil || flags.AllScopes == nil {
			return nil, fmt.Errorf("existing custom claim omitted its scope policy")
		}
	}
	var matched string
	switch attr {
	case "name":
		matched = item.Name
	case "displayName":
		matched = item.DisplayName
	case "userName":
		matched = item.UserName
	}
	if matched != name || !validID(item.ID) {
		return nil, fmt.Errorf("unexpected %s lookup result for %q", collection, name)
	}
	return item, nil
}

func validID(id string) bool {
	return id != "" && id != "." && id != ".." && !strings.ContainsAny(id, "/\\?#%")
}

func (d domain) ensureClaim(claim Claim) (string, error) {
	found, err := d.lookup("CustomClaims", "name", claim.Name, "id,name,value,expression,mode,tokenType,allScopes,scopes")
	if err != nil {
		return "", err
	}
	if found != nil {
		if !found.Claim.matches(claim) {
			return "", fmt.Errorf("existing custom claim %q differs from reviewed plan", claim.Name)
		}
		return "reused", nil
	}
	payload := struct {
		Schemas []string `json:"schemas"`
		Claim
	}{[]string{"urn:ietf:params:scim:schemas:oracle:idcs:CustomClaim"}, claim}
	_, err = d.request("POST", "CustomClaims", payload)
	return "created", err
}

func (d domain) ensureGroup(name string) (*entry, string, error) {
	found, err := d.lookup("Groups", "displayName", name, "id,displayName,members")
	if err != nil || found != nil {
		return found, "reused", err
	}
	raw, err := d.request("POST", "Groups", map[string]any{"schemas": []string{"urn:ietf:params:scim:schemas:core:2.0:Group"}, "displayName": name})
	if err != nil {
		return nil, "", err
	}
	var created entry
	if err = json.Unmarshal(raw, &created); err != nil || !validID(created.ID) || created.DisplayName != name {
		return nil, "", fmt.Errorf("group create response did not identify %q", name)
	}
	return &created, "created", nil
}

// Execute creates missing items and adds explicitly requested direct memberships.
// Successful earlier steps can be safely re-read when a later step fails.
func Execute(p Plan, out string, run Runner) ([]Step, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
	if run == nil {
		return nil, fmt.Errorf("OCI runner required")
	}
	var err error
	out, err = filepath.Abs(out)
	if err != nil {
		return nil, err
	}
	if err = os.MkdirAll(out, 0700); err != nil {
		return nil, err
	}
	d := domain{p.Target, out, run}
	ids := map[string]string{}
	for _, g := range p.Groups {
		for _, user := range g.Users {
			if _, ok := ids[user]; ok {
				continue
			}
			record, err := d.lookup("Users", "userName", user, "id,userName")
			if err != nil {
				return nil, err
			}
			if record == nil {
				return nil, fmt.Errorf("reviewed user %q not found", user)
			}
			ids[user] = record.ID
		}
	}
	steps := []Step{}
	action, err := d.ensureClaim(p.Claim)
	if err != nil {
		return steps, err
	}
	steps = append(steps, Step{p.Claim.Name, action})
	for _, g := range p.Groups {
		record, action, err := d.ensureGroup(g.Name)
		if err != nil {
			return steps, err
		}
		steps = append(steps, Step{g.Name, action})
		var missing []member
		for _, user := range g.Users {
			id := ids[user]
			if !slices.ContainsFunc(record.Members, func(m member) bool { return m.Value == id && (m.Type == "" || m.Type == "User") }) {
				missing = append(missing, member{id, "User"})
			}
		}
		if len(missing) == 0 {
			continue
		}
		payload := map[string]any{"schemas": []string{"urn:ietf:params:scim:api:messages:2.0:PatchOp"}, "Operations": []map[string]any{{"op": "add", "path": "members", "value": missing}}}
		if _, err = d.request("PATCH", "Groups/"+url.PathEscape(record.ID), payload); err != nil {
			return steps, err
		}
		steps = append(steps, Step{g.Name, "added-members"})
	}
	return steps, nil
}
