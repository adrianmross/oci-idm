package planner

import (
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

const (
	SchemaVersion                              = "oci-idm.plan.v1"
	APIVersion                                 = "oci-idm.oracle.com/v1"
	AppsPlanKind                               = "IdentityDomainAppsPlan"
	IDCSAppSchema                              = "urn:ietf:params:scim:schemas:oracle:idcs:App"
	IDCSUserSchema                             = "urn:ietf:params:scim:schemas:core:2.0:User"
	DefaultWebAppTemplateID                    = "CustomWebAppTemplateId"
	DefaultPublicAppTemplateID                 = "CustomBrowserMobileTemplateId"
	DefaultCLIRedirectURL                      = "http://127.0.0.1:8180/callback"
	AuthorizationCodeGrant                     = "authorization_code"
	RefreshTokenGrant                          = "refresh_token"
	ClientCredentialsGrant                     = "client_credentials"
	JWTBearerGrant                             = "urn:ietf:params:oauth:grant-type:jwt-bearer"
	TokenExchangeGrant                         = "urn:ietf:params:oauth:grant-type:token-exchange"
	OAuthClientCertificateSchema               = "urn:ietf:params:scim:schemas:oracle:idcs:OAuthClientCertificate"
	GrantSchema                                = "urn:ietf:params:scim:schemas:oracle:idcs:Grant"
	PatchOpSchema                              = "urn:ietf:params:scim:api:messages:2.0:PatchOp"
	AdministratorToAppGrant                    = "ADMINISTRATOR_TO_APP"
	AdministratorToUserGrant                   = "ADMINISTRATOR_TO_USER"
	AdministratorToGroupGrant                  = "ADMINISTRATOR_TO_GROUP"
	ServiceGeneric               ServiceKind   = "generic"
	ServiceOBP                   ServiceKind   = "obp"
	AppUser                      AppKind       = "user"
	AppService                   AppKind       = "service"
	AppJWT                       AppKind       = "jwt"
	AppJWTService                AppKind       = "jwt-service"
	AppJWTUser                   AppKind       = "jwt-user"
	AppWorkload                  AppKind       = "workload"
	ClientPublic                 ClientType    = "public"
	ClientConfidential           ClientType    = "confidential"
	PrincipalAuto                PrincipalMode = "auto"
	PrincipalNone                PrincipalMode = "none"
	PrincipalSameNameUser        PrincipalMode = "same-name-user"
	RolePresetNone               RolePreset    = "none"
	RolePresetOBPAdmin           RolePreset    = "obp-admin"
	RolePresetOBPRestClient      RolePreset    = "obp-rest-client"
	RolePresetOBPUser            RolePreset    = "obp-user"
	RolePresetOBPCAUser          RolePreset    = "obp-ca-user"
)

type ServiceKind string
type AppKind string
type ClientType string
type PrincipalMode string
type RolePreset string

type Options struct {
	Service              ServiceKind
	Platform             string
	Issuer               string
	Scope                string
	IDCSEndpoint         string
	ResourceAppID        string
	BaseAppName          string
	BaseAppDisplayName   string
	AppPrefix            string
	RedirectURL          string
	Include              []AppKind
	UserClientType       ClientType
	PrincipalMode        PrincipalMode
	PrincipalEmailDomain string
	RolePresets          []RolePreset
	AppRoleGrants        []AppRoleGrant
	CertificateAlias     string
	TemplateID           string
	UserTemplateID       string
	ServiceTemplateID    string
	JWTTemplateID        string
	AccessTokenExpiry    int
	RefreshTokenExpiry   int
	OCIContext           string
	OCIProfile           string
	OCIConfigPath        string
	OCIRegion            string
	TokenServiceName     string
	AppNames             map[AppKind]string
}

type Plan struct {
	APIVersion          string              `json:"apiVersion,omitempty"`
	Kind                string              `json:"kind,omitempty"`
	SchemaVersion       string              `json:"schemaVersion"`
	Target              Target              `json:"target"`
	BaseCloudServiceApp BaseCloudServiceApp `json:"baseCloudServiceApp,omitempty"`
	Apps                []AppPlan           `json:"apps"`
	Apply               ApplyPlan           `json:"apply"`
	Validation          ValidationPlan      `json:"validation"`
	SourceReferences    []string            `json:"sourceReferences"`
	InputSources        map[string]string   `json:"inputSources,omitempty"`
}

// ValidateContract accepts legacy plans that predate apiVersion and kind.
func (plan Plan) ValidateContract() error {
	if plan.APIVersion != "" && plan.APIVersion != APIVersion {
		return fmt.Errorf("unsupported apps plan apiVersion %q", plan.APIVersion)
	}
	if plan.Kind != "" && plan.Kind != AppsPlanKind {
		return fmt.Errorf("unsupported apps plan kind %q", plan.Kind)
	}
	return nil
}

type Target struct {
	Service              ServiceKind        `json:"service"`
	Platform             string             `json:"platform,omitempty"`
	Issuer               string             `json:"issuer"`
	Scope                string             `json:"scope"`
	IDCSEndpoint         string             `json:"idcsEndpoint"`
	IDCSAdminURL         string             `json:"idcsAdminUrl"`
	IDCSEndpointSource   string             `json:"idcsEndpointSource"`
	ResourceAppID        string             `json:"resourceAppId,omitempty"`
	RedirectURL          string             `json:"redirectUrl"`
	UserClientType       ClientType         `json:"userClientType"`
	PrincipalMode        PrincipalMode      `json:"principalMode"`
	PrincipalEmailDomain string             `json:"principalEmailDomain,omitempty"`
	TemplateIDs          map[AppKind]string `json:"templateIds"`
	OCIContext           string             `json:"ociContext,omitempty"`
	OCIProfile           string             `json:"ociProfile,omitempty"`
	OCIConfigPath        string             `json:"ociConfigPath,omitempty"`
	OCIRegion            string             `json:"ociRegion,omitempty"`
	TokenServiceName     string             `json:"tokenServiceName,omitempty"`
}

type BaseCloudServiceApp struct {
	Name             string   `json:"name,omitempty"`
	DisplayName      string   `json:"displayName,omitempty"`
	ExpectedBehavior []string `json:"expectedBehavior,omitempty"`
}

type AppPlan struct {
	Key                  AppKind        `json:"key"`
	Name                 string         `json:"name"`
	DisplayName          string         `json:"displayName"`
	Purpose              string         `json:"purpose"`
	ClientType           ClientType     `json:"clientType"`
	AllowedGrants        []string       `json:"allowedGrants"`
	RedirectURIs         []string       `json:"redirectUris"`
	AllowedScopes        []string       `json:"allowedScopes"`
	OCIPreCreate         []OCIAction    `json:"ociPreCreate,omitempty"`
	OCICreatePayloadFile string         `json:"ociCreatePayloadFile"`
	OCICreateCommand     string         `json:"ociCreateCommand"`
	OCICreatePayload     AppCreateInput `json:"ociCreatePayload"`
	Principal            *PrincipalPlan `json:"principal,omitempty"`
	OCIPostCreate        []OCIAction    `json:"ociPostCreate,omitempty"`
	RequiredPostCreate   []string       `json:"requiredPostCreate"`
	Usage                []string       `json:"usage"`
}

type PrincipalPlan struct {
	Mode           PrincipalMode   `json:"mode"`
	UserName       string          `json:"userName"`
	DisplayName    string          `json:"displayName"`
	PayloadFile    string          `json:"payloadFile"`
	CreateCommand  string          `json:"createCommand"`
	CreatePayload  UserCreateInput `json:"createPayload"`
	RequiredReason string          `json:"requiredReason"`
}

type ApplyPlan struct {
	PreCreateCommands  []string `json:"preCreateCommands,omitempty"`
	Commands           []string `json:"commands"`
	PostCreateCommands []string `json:"postCreateCommands,omitempty"`
}

type ValidationPlan struct {
	BeforeApply []string `json:"beforeApply"`
	AfterApply  []string `json:"afterApply"`
}

type AppCreateInput struct {
	Schemas            []string       `json:"schemas"`
	DisplayName        string         `json:"displayName"`
	Name               string         `json:"name"`
	Active             bool           `json:"active"`
	BasedOnTemplate    TemplateRef    `json:"basedOnTemplate"`
	IsOAuthClient      bool           `json:"isOAuthClient"`
	ClientType         ClientType     `json:"clientType"`
	AllowedGrants      []string       `json:"allowedGrants"`
	AllowedScopes      []AllowedScope `json:"allowedScopes"`
	RedirectURIs       []string       `json:"redirectUris,omitempty"`
	Certificates       []Certificate  `json:"certificates,omitempty"`
	AllURLSchemes      *bool          `json:"allUrlSchemesAllowed,omitempty"`
	BypassConsent      *bool          `json:"bypassConsent,omitempty"`
	AllowOffline       *bool          `json:"allowOffline,omitempty"`
	AccessTokenExpiry  *int           `json:"accessTokenExpiry,omitempty"`
	RefreshTokenExpiry *int           `json:"refreshTokenExpiry,omitempty"`
}

type UserCreateInput struct {
	Schemas     []string `json:"schemas"`
	UserName    string   `json:"userName"`
	DisplayName string   `json:"displayName,omitempty"`
	Name        Name     `json:"name"`
	Emails      []Email  `json:"emails,omitempty"`
	Active      bool     `json:"active"`
	Description string   `json:"description,omitempty"`
	ExternalID  string   `json:"externalId,omitempty"`
}

type Name struct {
	GivenName  string `json:"givenName,omitempty"`
	FamilyName string `json:"familyName,omitempty"`
	Formatted  string `json:"formatted,omitempty"`
}

type Email struct {
	Value   string `json:"value"`
	Type    string `json:"type,omitempty"`
	Primary bool   `json:"primary,omitempty"`
}

type TemplateRef struct {
	Value string `json:"value"`
}

type AllowedScope struct {
	FQS             string `json:"fqs"`
	IDOfDefiningApp string `json:"idOfDefiningApp,omitempty"`
}

type Certificate struct {
	CertAlias string `json:"certAlias"`
	KID       string `json:"kid,omitempty"`
}

type OCIAction struct {
	Key         string `json:"key"`
	Description string `json:"description"`
	PayloadFile string `json:"payloadFile,omitempty"`
	Command     string `json:"command"`
	Payload     any    `json:"payload,omitempty"`
}

type AppRoleGrant struct {
	DisplayName string `json:"displayName,omitempty"`
	ID          string `json:"id"`
	Source      string `json:"source,omitempty"`
	Required    bool   `json:"required,omitempty"`
}

type OAuthClientCertificateInput struct {
	Schemas               []string `json:"schemas"`
	CertificateAlias      string   `json:"certificateAlias"`
	X509Base64Certificate string   `json:"x509Base64Certificate"`
}

type GrantInput struct {
	Schemas        []string       `json:"schemas"`
	GrantMechanism string         `json:"grantMechanism"`
	App            ResourceRef    `json:"app"`
	Entitlement    EntitlementRef `json:"entitlement"`
	Grantee        ResourceRef    `json:"grantee"`
}

type ResourceRef struct {
	Value   string `json:"value"`
	Display string `json:"display,omitempty"`
	Type    string `json:"type,omitempty"`
	Ref     string `json:"$ref,omitempty"`
}

type EntitlementRef struct {
	AttributeName  string `json:"attributeName"`
	AttributeValue string `json:"attributeValue"`
}

func Build(options Options) (Plan, error) {
	service := options.Service
	if service == "" {
		service = ServiceGeneric
	}
	if service != ServiceGeneric && service != ServiceOBP {
		return Plan{}, fmt.Errorf("unsupported service %q", service)
	}

	issuer, err := required(options.Issuer, "issuer")
	if err != nil {
		return Plan{}, err
	}
	scope := strings.TrimSpace(options.Scope)
	if scope == "" {
		if service == ServiceOBP {
			scope = strings.TrimSpace(options.Platform)
		}
		if scope == "" {
			return Plan{}, errors.New("scope is required unless --service obp and --platform is set")
		}
	}

	redirectURL := firstNonEmpty(options.RedirectURL, DefaultCLIRedirectURL)
	userClientType := options.UserClientType
	if userClientType == "" {
		userClientType = ClientPublic
	}
	if userClientType != ClientPublic && userClientType != ClientConfidential {
		return Plan{}, fmt.Errorf("unsupported user client type %q", userClientType)
	}
	principalMode, err := resolvePrincipalMode(options.PrincipalMode, service)
	if err != nil {
		return Plan{}, err
	}

	idcsEndpoint, err := normalizeEndpoint(firstNonEmpty(options.IDCSEndpoint, issuer))
	if err != nil {
		return Plan{}, err
	}
	templateIDs, err := resolveTemplateIDs(options, userClientType)
	if err != nil {
		return Plan{}, err
	}
	includes := uniqueIncludes(options.Include)
	prefix := normalizePrefix(firstNonEmpty(
		options.AppPrefix,
		options.BaseAppName,
		options.BaseAppDisplayName,
		inferPrefix(options.Platform, scope),
	))

	ctx := buildContext{
		service:              service,
		prefix:               prefix,
		issuer:               issuer,
		scope:                scope,
		platform:             strings.TrimSpace(options.Platform),
		redirectURL:          redirectURL,
		idcsEndpoint:         idcsEndpoint,
		resourceAppID:        strings.TrimSpace(options.ResourceAppID),
		templateIDs:          templateIDs,
		userClientType:       userClientType,
		principalMode:        principalMode,
		principalEmailDomain: normalizeEmailDomain(options.PrincipalEmailDomain),
		appRoleGrants:        resolveAppRoleGrants(options.RolePresets, options.AppRoleGrants),
		certificateAlias:     strings.TrimSpace(options.CertificateAlias),
		accessTokenExpiry:    positivePtr(options.AccessTokenExpiry),
		refreshTokenExpiry:   positivePtr(options.RefreshTokenExpiry),
		ociProfile:           strings.TrimSpace(options.OCIProfile),
		ociConfigPath:        strings.TrimSpace(options.OCIConfigPath),
		ociRegion:            strings.TrimSpace(options.OCIRegion),
		appNames:             options.AppNames,
	}

	apps := make([]AppPlan, 0, len(includes))
	for _, include := range includes {
		apps = append(apps, buildApp(include, ctx))
	}

	commands := make([]string, 0, len(apps))
	preCreateCommands := []string{}
	postCreateCommands := []string{}
	for _, app := range apps {
		for _, action := range app.OCIPreCreate {
			preCreateCommands = append(preCreateCommands, action.Command)
		}
		commands = append(commands, app.OCICreateCommand)
		for _, action := range app.OCIPostCreate {
			postCreateCommands = append(postCreateCommands, action.Command)
		}
	}

	sourceReferences := []string{
		"OCI CLI: oci identity-domains app create",
		"OCI CLI: oci identity-domains user create",
		"OCI CLI: oci identity-domains o-auth-client-certificate create",
		"OCI CLI: oci identity-domains grant create",
		"Oracle Identity Domains: OAuth client applications and allowed grants",
		"Oracle Identity Domains: SCIM User resource",
		"Oracle Identity Domains: SCIM App resource",
	}
	if service == ServiceOBP {
		sourceReferences = append(sourceReferences, "Oracle Blockchain Platform REST API: OAuth authentication")
	}

	return Plan{
		APIVersion:    APIVersion,
		Kind:          AppsPlanKind,
		SchemaVersion: SchemaVersion,
		Target: Target{
			Service:              service,
			Platform:             strings.TrimSpace(options.Platform),
			Issuer:               issuer,
			Scope:                scope,
			IDCSEndpoint:         idcsEndpoint,
			IDCSAdminURL:         idcsEndpoint + "/admin/v1/",
			IDCSEndpointSource:   endpointSource(options.IDCSEndpoint),
			ResourceAppID:        strings.TrimSpace(options.ResourceAppID),
			RedirectURL:          redirectURL,
			UserClientType:       userClientType,
			PrincipalMode:        principalMode,
			PrincipalEmailDomain: normalizeEmailDomain(options.PrincipalEmailDomain),
			TemplateIDs:          templateIDs,
			OCIContext:           strings.TrimSpace(options.OCIContext),
			OCIProfile:           strings.TrimSpace(options.OCIProfile),
			OCIConfigPath:        strings.TrimSpace(options.OCIConfigPath),
			OCIRegion:            strings.TrimSpace(options.OCIRegion),
			TokenServiceName:     strings.TrimSpace(options.TokenServiceName),
		},
		BaseCloudServiceApp: baseCloudServiceApp(service, options),
		Apps:                apps,
		Apply: ApplyPlan{
			PreCreateCommands:  preCreateCommands,
			Commands:           commands,
			PostCreateCommands: postCreateCommands,
		},
		Validation:       validationPlan(service, principalMode),
		SourceReferences: sourceReferences,
	}, nil
}

func ParseIncludes(value string) ([]AppKind, error) {
	if strings.TrimSpace(value) == "" {
		return defaultIncludes(), nil
	}
	parts := strings.Split(value, ",")
	includes := make([]AppKind, 0, len(parts))
	for _, part := range parts {
		key := AppKind(strings.TrimSpace(part))
		if key == "" {
			continue
		}
		switch key {
		case AppJWT:
			includes = append(includes, AppJWTService, AppJWTUser, AppWorkload)
		case AppUser, AppService, AppJWTService, AppJWTUser, AppWorkload:
			includes = append(includes, key)
		default:
			return nil, fmt.Errorf("unsupported app include %q", key)
		}
	}
	return uniqueIncludes(includes), nil
}

func ParseClientType(value string) (ClientType, error) {
	switch strings.TrimSpace(value) {
	case "":
		return "", nil
	case string(ClientPublic):
		return ClientPublic, nil
	case string(ClientConfidential):
		return ClientConfidential, nil
	default:
		return "", fmt.Errorf("unsupported client type %q", value)
	}
}

func ParsePrincipalMode(value string) (PrincipalMode, error) {
	switch strings.TrimSpace(value) {
	case "":
		return "", nil
	case string(PrincipalAuto):
		return PrincipalAuto, nil
	case string(PrincipalNone):
		return PrincipalNone, nil
	case string(PrincipalSameNameUser):
		return PrincipalSameNameUser, nil
	default:
		return "", fmt.Errorf("unsupported principal mode %q", value)
	}
}

func resolvePrincipalMode(value PrincipalMode, service ServiceKind) (PrincipalMode, error) {
	parsed, err := ParsePrincipalMode(string(value))
	if err != nil {
		return "", err
	}
	if parsed == "" || parsed == PrincipalAuto {
		if service == ServiceOBP {
			return PrincipalSameNameUser, nil
		}
		return PrincipalNone, nil
	}
	return parsed, nil
}

func ParseRolePresets(value string) ([]RolePreset, error) {
	if strings.TrimSpace(value) == "" {
		return nil, nil
	}
	parts := strings.Split(value, ",")
	presets := make([]RolePreset, 0, len(parts))
	seen := map[RolePreset]bool{}
	for _, part := range parts {
		preset := RolePreset(strings.TrimSpace(part))
		if preset == "" || preset == RolePresetNone {
			continue
		}
		switch preset {
		case RolePresetOBPAdmin, RolePresetOBPRestClient, RolePresetOBPUser, RolePresetOBPCAUser:
		default:
			return nil, fmt.Errorf("unsupported role preset %q", preset)
		}
		if seen[preset] {
			continue
		}
		seen[preset] = true
		presets = append(presets, preset)
	}
	return presets, nil
}

func ParseAppRoleGrants(value string) ([]AppRoleGrant, error) {
	if strings.TrimSpace(value) == "" {
		return nil, nil
	}
	parts := strings.Split(value, ",")
	grants := make([]AppRoleGrant, 0, len(parts))
	seen := map[string]bool{}
	seenID := map[string]bool{}
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		display, id, ok := strings.Cut(part, "=")
		if !ok {
			id = display
			display = ""
		}
		id = strings.TrimSpace(id)
		display = strings.TrimSpace(display)
		if id == "" {
			return nil, fmt.Errorf("empty app role id in %q", value)
		}
		key := display
		if key == "" {
			key = id
		}
		key = strings.ToUpper(key)
		idKey := strings.ToUpper(id)
		if seen[key] || seenID[idKey] {
			continue
		}
		seen[key] = true
		seenID[idKey] = true
		grants = append(grants, AppRoleGrant{DisplayName: display, ID: id, Source: "custom", Required: true})
	}
	return grants, nil
}

func resolveAppRoleGrants(presets []RolePreset, custom []AppRoleGrant) []AppRoleGrant {
	merged := []AppRoleGrant{}
	index := map[string]int{}
	add := func(grant AppRoleGrant) {
		key := strings.ToUpper(firstNonEmpty(grant.DisplayName, grant.ID))
		if key == "" {
			return
		}
		if existing, ok := index[key]; ok {
			if grant.ID != "" && !strings.HasPrefix(grant.ID, "<") {
				merged[existing].ID = grant.ID
			}
			if grant.DisplayName != "" {
				merged[existing].DisplayName = grant.DisplayName
			}
			if grant.Source != "" {
				merged[existing].Source = grant.Source
			}
			merged[existing].Required = merged[existing].Required || grant.Required
			return
		}
		index[key] = len(merged)
		merged = append(merged, grant)
	}
	for _, preset := range presets {
		for _, grant := range rolePresetGrants(preset) {
			add(grant)
		}
	}
	for _, grant := range custom {
		if grant.Source == "" {
			grant.Source = "custom"
		}
		grant.Required = true
		add(grant)
	}
	return merged
}

func rolePresetGrants(preset RolePreset) []AppRoleGrant {
	switch preset {
	case RolePresetOBPAdmin:
		return []AppRoleGrant{
			{DisplayName: "ADMIN", ID: "<ADMIN-app-role-id>", Source: string(preset), Required: true},
			{DisplayName: "REST_CLIENT", ID: "<REST_CLIENT-app-role-id>", Source: string(preset), Required: true},
		}
	case RolePresetOBPRestClient:
		return []AppRoleGrant{{DisplayName: "REST_CLIENT", ID: "<REST_CLIENT-app-role-id>", Source: string(preset), Required: true}}
	case RolePresetOBPUser:
		return []AppRoleGrant{{DisplayName: "USER", ID: "<USER-app-role-id>", Source: string(preset), Required: true}}
	case RolePresetOBPCAUser:
		return []AppRoleGrant{{DisplayName: "CA_USER", ID: "<CA_USER-app-role-id>", Source: string(preset), Required: true}}
	default:
		return nil
	}
}

type buildContext struct {
	service              ServiceKind
	prefix               string
	issuer               string
	scope                string
	platform             string
	redirectURL          string
	idcsEndpoint         string
	resourceAppID        string
	templateIDs          map[AppKind]string
	userClientType       ClientType
	principalMode        PrincipalMode
	principalEmailDomain string
	appRoleGrants        []AppRoleGrant
	certificateAlias     string
	accessTokenExpiry    *int
	refreshTokenExpiry   *int
	ociProfile           string
	ociConfigPath        string
	ociRegion            string
	appNames             map[AppKind]string
}

func buildApp(kind AppKind, ctx buildContext) AppPlan {
	switch kind {
	case AppUser:
		return appPlan(appInput{
			kind:               AppUser,
			name:               appName(ctx, AppUser, ctx.prefix+"-cli-user"),
			displayName:        title(ctx.prefix) + " CLI User Auth",
			purpose:            "MFA-capable local human authorization-code flow for a CLI token helper.",
			clientType:         ctx.userClientType,
			grants:             []string{AuthorizationCodeGrant, RefreshTokenGrant},
			redirectURIs:       []string{ctx.redirectURL},
			scope:              ctx.scope,
			resourceAppID:      ctx.resourceAppID,
			templateID:         ctx.templateIDs[AppUser],
			idcsEndpoint:       ctx.idcsEndpoint,
			ociProfile:         ctx.ociProfile,
			ociConfigPath:      ctx.ociConfigPath,
			ociRegion:          ctx.ociRegion,
			allowOffline:       true,
			bypassConsent:      true,
			accessExpiry:       ctx.accessTokenExpiry,
			refreshExpiry:      ctx.refreshTokenExpiry,
			requiredPostCreate: userPostCreate(ctx),
			usage: []string{
				"Configure your token helper with the issuer, generated client id, scope, and redirect URL.",
				"Run the helper's authorization-code flow once to cache a refresh token.",
			},
		})
	case AppService:
		return appPlan(appInput{
			kind:                 AppService,
			name:                 appName(ctx, AppService, ctx.prefix+"-service"),
			displayName:          title(ctx.prefix) + " Service Client",
			purpose:              "Confidential OAuth client for non-human client-credentials automation.",
			clientType:           ClientConfidential,
			grants:               []string{ClientCredentialsGrant},
			scope:                ctx.scope,
			resourceAppID:        ctx.resourceAppID,
			templateID:           ctx.templateIDs[AppService],
			idcsEndpoint:         ctx.idcsEndpoint,
			ociProfile:           ctx.ociProfile,
			ociConfigPath:        ctx.ociConfigPath,
			ociRegion:            ctx.ociRegion,
			bypassConsent:        true,
			accessExpiry:         ctx.accessTokenExpiry,
			appRoleGrants:        ctx.appRoleGrants,
			principalMode:        ctx.principalMode,
			principalEmailDomain: ctx.principalEmailDomain,
			requiredPostCreate: []string{
				"Store the generated client id and secret in a secret manager or CI secret store.",
				"Grant only the target service roles required by this automation identity.",
			},
			usage: []string{
				"Use grant_type=client_credentials with the generated client id, client secret, and requested scope.",
			},
		})
	case AppJWTService:
		return appPlan(appInput{
			kind:                 AppJWTService,
			name:                 appName(ctx, AppJWTService, ctx.prefix+"-service-jwt"),
			displayName:          title(ctx.prefix) + " Service JWT Client",
			purpose:              "Confidential OAuth client for service-account client credentials with JWT client assertion authentication.",
			clientType:           ClientConfidential,
			grants:               []string{ClientCredentialsGrant},
			scope:                ctx.scope,
			resourceAppID:        ctx.resourceAppID,
			templateID:           ctx.templateIDs[AppJWTService],
			idcsEndpoint:         ctx.idcsEndpoint,
			ociProfile:           ctx.ociProfile,
			ociConfigPath:        ctx.ociConfigPath,
			ociRegion:            ctx.ociRegion,
			bypassConsent:        true,
			accessExpiry:         ctx.accessTokenExpiry,
			certAlias:            ctx.certificateAlias,
			clientCert:           true,
			appRoleGrants:        ctx.appRoleGrants,
			principalMode:        ctx.principalMode,
			principalEmailDomain: ctx.principalEmailDomain,
			requiredPostCreate: []string{
				"Register the client assertion signing certificate or public key trusted by the identity domain.",
				"Grant only the target service roles required by this automation identity.",
			},
			usage: []string{
				"Use grant_type=client_credentials with client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer.",
				"Use oci-context --flow jwt-client-credentials with --client-assertion-command or --private-key-file.",
				"For OCI Identity Domains, set the local client assertion audience to https://identity.oraclecloud.com/ when the token endpoint rejects token-endpoint audiences.",
			},
		})
	case AppJWTUser:
		return appPlan(appInput{
			kind:          AppJWTUser,
			name:          appName(ctx, AppJWTUser, ctx.prefix+"-user-jwt"),
			displayName:   title(ctx.prefix) + " User JWT Bearer",
			purpose:       "Confidential OAuth client for trusted JWT bearer assertions that represent a user or mapped subject.",
			clientType:    ClientConfidential,
			grants:        []string{JWTBearerGrant},
			scope:         ctx.scope,
			resourceAppID: ctx.resourceAppID,
			templateID:    ctx.templateIDs[AppJWTUser],
			idcsEndpoint:  ctx.idcsEndpoint,
			ociProfile:    ctx.ociProfile,
			ociConfigPath: ctx.ociConfigPath,
			ociRegion:     ctx.ociRegion,
			bypassConsent: true,
			accessExpiry:  ctx.accessTokenExpiry,
			appRoleGrants: ctx.appRoleGrants,
			requiredPostCreate: []string{
				"Register the assertion signing certificate or trust material required by the identity domain.",
				"Map the asserted subject to an identity that has only the target service roles it needs.",
			},
			usage: []string{
				"Use grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer with the signed assertion.",
				"Use oci-context --flow jwt-bearer with --assertion-command or --assertion-file.",
			},
		})
	case AppWorkload:
		return appPlan(appInput{
			kind:          AppWorkload,
			name:          appName(ctx, AppWorkload, ctx.prefix+"-workload-federation"),
			displayName:   title(ctx.prefix) + " Workload Federation",
			purpose:       "Confidential OAuth client for exchanging trusted workload identity tokens for service access tokens.",
			clientType:    ClientConfidential,
			grants:        []string{TokenExchangeGrant},
			scope:         ctx.scope,
			resourceAppID: ctx.resourceAppID,
			templateID:    ctx.templateIDs[AppWorkload],
			idcsEndpoint:  ctx.idcsEndpoint,
			ociProfile:    ctx.ociProfile,
			ociConfigPath: ctx.ociConfigPath,
			ociRegion:     ctx.ociRegion,
			bypassConsent: true,
			accessExpiry:  ctx.accessTokenExpiry,
			appRoleGrants: ctx.appRoleGrants,
			requiredPostCreate: []string{
				"Register or configure the external workload issuer trust, audience, and claim mapping required by the identity domain.",
				"Grant only the target service roles required by the workload identity.",
			},
			usage: []string{
				"Use grant_type=urn:ietf:params:oauth:grant-type:token-exchange with a JWT subject token.",
				"Use oci-context --flow token-exchange with --subject-token-command for GitHub OIDC, Kubernetes, or other workload JWTs.",
			},
		})
	default:
		return AppPlan{}
	}
}

func appName(ctx buildContext, kind AppKind, fallback string) string {
	if ctx.appNames != nil {
		if name := strings.TrimSpace(ctx.appNames[kind]); name != "" {
			return name
		}
	}
	return fallback
}

type appInput struct {
	kind                 AppKind
	name                 string
	displayName          string
	purpose              string
	clientType           ClientType
	grants               []string
	redirectURIs         []string
	scope                string
	resourceAppID        string
	templateID           string
	idcsEndpoint         string
	ociProfile           string
	ociConfigPath        string
	ociRegion            string
	allowOffline         bool
	bypassConsent        bool
	certAlias            string
	clientCert           bool
	appRoleGrants        []AppRoleGrant
	principalMode        PrincipalMode
	principalEmailDomain string
	accessExpiry         *int
	refreshExpiry        *int
	requiredPostCreate   []string
	usage                []string
}

func appPlan(input appInput) AppPlan {
	payloadFile := input.name + ".json"
	payload := AppCreateInput{
		Schemas:         []string{IDCSAppSchema},
		DisplayName:     input.displayName,
		Name:            input.name,
		Active:          true,
		BasedOnTemplate: TemplateRef{Value: input.templateID},
		IsOAuthClient:   true,
		ClientType:      input.clientType,
		AllowedGrants:   append([]string{}, input.grants...),
		AllowedScopes:   []AllowedScope{{FQS: input.scope, IDOfDefiningApp: input.resourceAppID}},
		RedirectURIs:    append([]string{}, input.redirectURIs...),
	}
	preCreate := []OCIAction{}
	postCreate := []OCIAction{}
	if input.clientCert {
		certAlias := firstNonEmpty(input.certAlias, input.name+"-cert")
		payload.Certificates = []Certificate{{CertAlias: certAlias, KID: certAlias}}
		preCreate = append(preCreate, oauthClientCertificateAction(input, certAlias))
	}
	if hasNonHTTPSRedirect(input.redirectURIs) {
		payload.AllURLSchemes = boolPtr(true)
	}
	if input.bypassConsent {
		payload.BypassConsent = boolPtr(true)
	}
	if input.allowOffline {
		payload.AllowOffline = boolPtr(true)
	}
	payload.AccessTokenExpiry = input.accessExpiry
	payload.RefreshTokenExpiry = input.refreshExpiry
	if input.resourceAppID != "" {
		for _, grant := range input.appRoleGrants {
			postCreate = append(postCreate, appRoleGrantAction(input, grant))
		}
	}
	principal := principalPlan(input)
	if principal != nil {
		postCreate = append(postCreate, principalUserCreateAction(input, *principal))
		for _, grant := range input.appRoleGrants {
			postCreate = append(postCreate, principalUserRoleGrantAction(input, *principal, grant))
		}
		input.requiredPostCreate = append(input.requiredPostCreate,
			"Create or reuse the same-name principal user "+input.name+" before validating target-service authorization.",
			"Replace <principal-user-id-for-"+input.name+"> in user-role grant payloads with the created or existing user id.",
		)
	}

	return AppPlan{
		Key:                  input.kind,
		Name:                 input.name,
		DisplayName:          input.displayName,
		Purpose:              input.purpose,
		ClientType:           input.clientType,
		AllowedGrants:        append([]string{}, input.grants...),
		RedirectURIs:         append([]string{}, input.redirectURIs...),
		AllowedScopes:        []string{input.scope},
		OCIPreCreate:         preCreate,
		OCICreatePayloadFile: payloadFile,
		OCICreateCommand:     IdentityDomainsCommand(input.idcsEndpoint, input.ociProfile, input.ociConfigPath, input.ociRegion, "app", "create", "--from-json file://"+payloadFile),
		OCICreatePayload:     payload,
		Principal:            principal,
		OCIPostCreate:        postCreate,
		RequiredPostCreate:   append([]string{}, input.requiredPostCreate...),
		Usage:                append([]string{}, input.usage...),
	}
}

func oauthClientCertificateAction(input appInput, certAlias string) OCIAction {
	payloadFile := input.name + "-oauth-client-certificate.json"
	return OCIAction{
		Key:         "register-oauth-client-certificate",
		Description: "Register the JWT client assertion public certificate before creating or patching the app certificate reference.",
		PayloadFile: payloadFile,
		Command:     IdentityDomainsCommand(input.idcsEndpoint, input.ociProfile, input.ociConfigPath, input.ociRegion, "o-auth-client-certificate", "create", "--from-json file://"+payloadFile),
		Payload: OAuthClientCertificateInput{
			Schemas:               []string{OAuthClientCertificateSchema},
			CertificateAlias:      certAlias,
			X509Base64Certificate: "<x509-base64-der-certificate>",
		},
	}
}

func appRoleGrantAction(input appInput, grant AppRoleGrant) OCIAction {
	roleLabel := firstNonEmpty(grant.DisplayName, grant.ID)
	payloadFile := input.name + "-grant-" + normalizePrefix(roleLabel) + ".json"
	createdAppID := "<created-app-id>"
	appRefBase := adminResourceBase(input.idcsEndpoint)
	return OCIAction{
		Key:         "grant-app-role",
		Description: "Grant target service app role " + roleLabel + " to the created OAuth client app.",
		PayloadFile: payloadFile,
		Command:     IdentityDomainsCommand(input.idcsEndpoint, input.ociProfile, input.ociConfigPath, input.ociRegion, "grant", "create", "--from-json file://"+payloadFile),
		Payload: GrantInput{
			Schemas:        []string{GrantSchema},
			GrantMechanism: AdministratorToAppGrant,
			App: ResourceRef{
				Value: input.resourceAppID,
				Ref:   appRefBase + "/Apps/" + input.resourceAppID,
			},
			Entitlement: EntitlementRef{
				AttributeName:  "appRoles",
				AttributeValue: grant.ID,
			},
			Grantee: ResourceRef{
				Value: createdAppID,
				Type:  "App",
				Ref:   appRefBase + "/Apps/" + createdAppID,
			},
		},
	}
}

func principalPlan(input appInput) *PrincipalPlan {
	if input.principalMode != PrincipalSameNameUser {
		return nil
	}
	if input.kind != AppService && input.kind != AppJWTService {
		return nil
	}
	userName := input.name
	displayName := input.displayName + " Principal"
	payloadFile := input.name + "-principal-user.json"
	emailDomain := normalizeEmailDomain(input.principalEmailDomain)
	email := userName + "@" + emailDomain
	return &PrincipalPlan{
		Mode:          PrincipalSameNameUser,
		UserName:      userName,
		DisplayName:   displayName,
		PayloadFile:   payloadFile,
		CreateCommand: IdentityDomainsCommand(input.idcsEndpoint, input.ociProfile, input.ociConfigPath, input.ociRegion, "user", "create", "--from-json file://"+payloadFile),
		CreatePayload: UserCreateInput{
			Schemas:     []string{IDCSUserSchema},
			UserName:    userName,
			DisplayName: displayName,
			Name: Name{
				GivenName:  title(input.name),
				FamilyName: "Principal",
				Formatted:  displayName,
			},
			Emails: []Email{{
				Value:   email,
				Type:    "work",
				Primary: true,
			}},
			Active:      true,
			Description: "Service principal user for OAuth client " + input.name + ". Some target services authorize client-credentials tokens by resolving token sub/client_id as an Identity Domains userName.",
			ExternalID:  "oci-idm:" + input.name,
		},
		RequiredReason: "Target service authorizes the OAuth token subject as an Identity Domains user name.",
	}
}

func principalUserCreateAction(input appInput, principal PrincipalPlan) OCIAction {
	return OCIAction{
		Key:         "create-principal-user",
		Description: "Create same-name Identity Domains user " + principal.UserName + " for target-service authorization.",
		PayloadFile: principal.PayloadFile,
		Command:     principal.CreateCommand,
		Payload:     principal.CreatePayload,
	}
}

func principalUserRoleGrantAction(input appInput, principal PrincipalPlan, grant AppRoleGrant) OCIAction {
	roleLabel := firstNonEmpty(grant.DisplayName, grant.ID)
	payloadFile := input.name + "-principal-user-grant-" + normalizePrefix(roleLabel) + ".json"
	principalUserID := "<principal-user-id-for-" + input.name + ">"
	appRefBase := adminResourceBase(input.idcsEndpoint)
	return OCIAction{
		Key:         "grant-principal-user-app-role",
		Description: "Grant target service app role " + roleLabel + " to same-name principal user " + principal.UserName + ".",
		PayloadFile: payloadFile,
		Command:     IdentityDomainsCommand(input.idcsEndpoint, input.ociProfile, input.ociConfigPath, input.ociRegion, "grant", "create", "--from-json file://"+payloadFile),
		Payload: GrantInput{
			Schemas:        []string{GrantSchema},
			GrantMechanism: AdministratorToUserGrant,
			App: ResourceRef{
				Value: input.resourceAppID,
				Ref:   appRefBase + "/Apps/" + input.resourceAppID,
			},
			Entitlement: EntitlementRef{
				AttributeName:  "appRoles",
				AttributeValue: grant.ID,
			},
			Grantee: ResourceRef{
				Value: principalUserID,
				Type:  "User",
				Ref:   appRefBase + "/Users/" + principalUserID,
			},
		},
	}
}

func userPostCreate(ctx buildContext) []string {
	steps := []string{
		"Copy the generated client id into your token helper configuration.",
	}
	if ctx.userClientType == ClientConfidential {
		steps = append(steps, "Store the generated client secret outside source control.")
	} else {
		steps = append(steps, "No client secret is required when using PKCE with a public client.")
	}
	steps = append(steps, "Assign the app to users or groups if the identity domain enforces application grants.")
	return steps
}

func baseCloudServiceApp(service ServiceKind, options Options) BaseCloudServiceApp {
	if service != ServiceOBP {
		return BaseCloudServiceApp{}
	}
	return BaseCloudServiceApp{
		Name:        strings.TrimSpace(options.BaseAppName),
		DisplayName: strings.TrimSpace(options.BaseAppDisplayName),
		ExpectedBehavior: []string{
			"Treat the generated Oracle Blockchain Platform CloudGate app as service-owned and non-mutated.",
			"Do not use a CloudGate callback for CLI authorization-code handoff because CloudGate consumes the code.",
			"Create companion OAuth clients for local user auth, service automation, service-account JWT, user JWT bearer, and workload federation flows.",
		},
	}
}

func validationPlan(service ServiceKind, principalMode PrincipalMode) ValidationPlan {
	before := []string{
		"Confirm the OCI Identity Domains endpoint is the identity-domain base URL.",
		"Confirm the requested scope belongs to the target service resource.",
		"Review every payload before applying it with OCI CLI.",
	}
	after := []string{
		"Grant the app to the intended users, groups, or automation identities.",
		"Store generated secrets only in an approved secret manager.",
		"Run a read-only target-service validation before granting write or admin roles.",
	}
	if service == ServiceOBP {
		after = append(after,
			"Grant Oracle Blockchain Platform administrator access for deploy or console-admin APIs.",
			"Grant REST_CLIENT and REST proxy enrollment for REST proxy chaincode calls.",
		)
	}
	if principalMode == PrincipalSameNameUser {
		after = append(after,
			"Confirm the OAuth client id and principal userName are identical.",
			"Confirm the principal user has the required target service app-role grants.",
		)
	}
	return ValidationPlan{BeforeApply: before, AfterApply: after}
}

func resolveTemplateIDs(options Options, userClientType ClientType) (map[AppKind]string, error) {
	defaultUser := DefaultWebAppTemplateID
	if userClientType == ClientPublic {
		defaultUser = DefaultPublicAppTemplateID
	}
	values := map[AppKind]string{
		AppUser:       firstNonEmpty(options.UserTemplateID, options.TemplateID, defaultUser),
		AppService:    firstNonEmpty(options.ServiceTemplateID, options.TemplateID, DefaultWebAppTemplateID),
		AppJWTService: firstNonEmpty(options.JWTTemplateID, options.ServiceTemplateID, options.TemplateID, DefaultWebAppTemplateID),
		AppJWTUser:    firstNonEmpty(options.JWTTemplateID, options.TemplateID, DefaultWebAppTemplateID),
		AppWorkload:   firstNonEmpty(options.JWTTemplateID, options.TemplateID, DefaultWebAppTemplateID),
	}
	for key, value := range values {
		if strings.TrimSpace(value) == "" {
			return nil, fmt.Errorf("template id for %s is required", key)
		}
		values[key] = strings.TrimSpace(value)
	}
	return values, nil
}

func uniqueIncludes(includes []AppKind) []AppKind {
	if len(includes) == 0 {
		includes = defaultIncludes()
	}
	seen := map[AppKind]bool{}
	out := make([]AppKind, 0, len(includes))
	for _, include := range includes {
		if include == AppJWT {
			for _, expanded := range []AppKind{AppJWTService, AppJWTUser, AppWorkload} {
				if seen[expanded] {
					continue
				}
				seen[expanded] = true
				out = append(out, expanded)
			}
			continue
		}
		if seen[include] {
			continue
		}
		seen[include] = true
		out = append(out, include)
	}
	return out
}

func defaultIncludes() []AppKind {
	return []AppKind{AppUser, AppService, AppJWTService, AppJWTUser, AppWorkload}
}

func normalizeEndpoint(value string) (string, error) {
	trimmed, err := required(value, "idcs endpoint")
	if err != nil {
		return "", err
	}
	parsed, err := url.Parse(trimmed)
	if err != nil {
		return "", err
	}
	if parsed.Scheme != "https" || parsed.Host == "" {
		return "", fmt.Errorf("identity domain endpoint must be an https URL")
	}
	return parsed.Scheme + "://" + parsed.Host, nil
}

func endpointSource(value string) string {
	if strings.TrimSpace(value) == "" {
		return "derived_from_issuer"
	}
	return "option"
}

func inferPrefix(platform string, scope string) string {
	for _, candidate := range []string{platform, scope} {
		if parsed, err := url.Parse(candidate); err == nil && parsed.Hostname() != "" {
			return strings.Split(parsed.Hostname(), ".")[0]
		}
	}
	return "oci-service"
}

var unsafeName = regexp.MustCompile(`[^A-Za-z0-9-]+`)

func normalizePrefix(value string) string {
	normalized := strings.TrimSuffix(strings.TrimSpace(value), "_APPID")
	normalized = unsafeName.ReplaceAllString(normalized, "-")
	normalized = strings.Trim(normalized, "-")
	normalized = strings.ToLower(normalized)
	if normalized == "" {
		return "oci-service"
	}
	return normalized
}

func title(value string) string {
	parts := strings.Split(value, "-")
	for i, part := range parts {
		if part == "" {
			continue
		}
		parts[i] = strings.ToUpper(part[:1]) + part[1:]
	}
	return strings.Join(parts, " ")
}

func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\"'\"'") + "'"
}

func adminResourceBase(endpoint string) string {
	parsed, err := url.Parse(endpoint)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return strings.TrimRight(endpoint, "/") + "/admin/v1"
	}
	host := parsed.Host
	if !strings.Contains(host, ":") {
		host += ":443"
	}
	return parsed.Scheme + "://" + host + "/admin/v1"
}

func IdentityDomainsCommand(endpoint, profile, configPath, region, resource, action string, args ...string) string {
	parts := []string{
		"oci identity-domains",
		resource,
		action,
		"--endpoint " + shellQuote(endpoint),
	}
	if strings.TrimSpace(profile) != "" {
		parts = append(parts, "--profile "+shellQuote(strings.TrimSpace(profile)))
	}
	if strings.TrimSpace(configPath) != "" {
		parts = append(parts, "--config-file "+shellQuote(strings.TrimSpace(configPath)))
	}
	if strings.TrimSpace(region) != "" {
		parts = append(parts, "--region "+shellQuote(strings.TrimSpace(region)))
	}
	parts = append(parts, args...)
	return strings.Join(parts, " ")
}

func required(value string, name string) (string, error) {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return "", fmt.Errorf("%s is required", name)
	}
	return trimmed, nil
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			return trimmed
		}
	}
	return ""
}

func boolPtr(value bool) *bool {
	return &value
}

func hasNonHTTPSRedirect(redirectURIs []string) bool {
	for _, redirectURI := range redirectURIs {
		if strings.TrimSpace(redirectURI) != "" && !strings.HasPrefix(strings.ToLower(strings.TrimSpace(redirectURI)), "https://") {
			return true
		}
	}
	return false
}

func positivePtr(value int) *int {
	if value <= 0 {
		return nil
	}
	return &value
}

func normalizeEmailDomain(value string) string {
	trimmed := strings.TrimSpace(value)
	trimmed = strings.TrimPrefix(trimmed, "@")
	if trimmed == "" {
		return "example.invalid"
	}
	return trimmed
}
