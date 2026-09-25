# oci-idm

`oci-idm` plans OCI Identity Domains apps, grants, and token-helper handoffs for
CLI and automation use.

The tool is intentionally review-first. It emits public OCI CLI payloads,
helper scripts, and `oci-context` handoff files. It does not store secrets or
create resources unless you explicitly run the generated OCI CLI commands.

`oci-identity-apps` remains a compatibility command for the original app-focused
name.

## Why This Exists

Oracle cloud services often create service-owned web applications in OCI
Identity Domains. Those generated apps are useful source context, but they are
not always the right clients for local CLI login, service accounts, JWT
assertions, or workload federation.

`oci-idm` plans companion identity resources for common flows:

- `user`: Authorization Code + Refresh Token for local CLI login helpers.
- `service`: Client Credentials for non-human automation.
- `jwt-service`: service-account Client Credentials with JWT client assertion.
- `jwt-user`: JWT Bearer assertion exchange for user or subject representation.
- `workload`: token exchange for trusted workload identity JWTs.

The `jwt` include expands to `jwt-service,jwt-user,workload`.

## Install

Homebrew:

```bash
brew install adrianmross/tap/oci-idm
```

npm:

```bash
npm install -g @adrianmross/oci-idm
```

GitHub Packages requires npm authentication, even for public packages:

```bash
export GITHUB_TOKEN="<github-token>"
npm config set @adrianmross:registry https://npm.pkg.github.com
npm config set //npm.pkg.github.com/:_authToken "$GITHUB_TOKEN"
npm install -g @adrianmross/oci-idm
```

The npm package builds the Go CLI during install, so Go 1.25.6 or newer must be
available on `PATH`.

## Basic Flow

By default, `oci-idm` reads the current `oci-context` for OCI CLI defaults:

- `oci-context export -f json` supplies the current context name, profile, and
  region, plus `current_service` when one is selected.
- `oci-context paths -o json` supplies the OCI config file path.
- `oci-context auth service list -o json` supplies OAuth issuer and scope
  defaults when a matching token service exists.

Explicit flags always win. Use `--oci-context=false` to disable this defaulting,
`--oci-context-bin` when testing another binary, and `--oci-context-service`
when a command should read issuer/scope from a named token service instead of
the current `oci-context` auth target.
Commands with structured output accept `-o` or `--output`; `--format` remains
available as a compatibility alias.
Commands that read a plan accept `-f` or `--file`; `--plan` remains available
as a compatibility alias.
The preferred command shape is `oci-idm <verb> <resource> [flags]`, similar to
`kubectl`: `get defaults`, `get domains`, `get services`, `get service-apps`, `clone app`, `plan apps`,
`doctor plan`, `materialize plan`, `apply plan`, `validate plan`, and `export`.

Inspect the resolved defaults before planning:

```bash
oci-idm get defaults --service obp -o text
```

List Identity Domains through the current context. This emits the read-only OCI
CLI command, using explicit flags first, then OCI CLI environment overrides,
then the selected `oci-context`; it never creates a domain:

```bash
oci-idm get domains -o text
oci-idm describe domain --domain-id example-domain-ocid -o text
```

For a dedicated domain, plan before creating it. The apply command reuses an
exact display-name match; otherwise `--confirm` creates the domain and waits
until the lifecycle is `ACTIVE`:

```bash
oci-idm plan domain \
  --name example-control-plane \
  --description "Example Control Plane identity domain" \
  --license-type <approved-license-type> \
  -o json > domain-plan.json

oci-idm apply domain -f domain-plan.json --confirm
```

The plan defaults the compartment and home region from the selected
`oci-context`; pass explicit flags when the domain belongs elsewhere.

`oci-idm get services` lists the metadata-only token services owned by the
current `oci-context`. Creating, selecting, and authenticating a token service
remain `oci-context` responsibilities.

## Control Plane OIDC export

Render a reviewed, secret-free OBPEE Control Plane OIDC payload from an issuer,
OAuth client ID, and reusable policy. The command reads standard OIDC discovery;
it does not call the Control Plane or Kubernetes.

```bash
oci-idm export \
  --shape obpee-cp \
  --domain https://example.identity.oraclecloud.com \
  --app example-control-plane-client-id \
  --control-plane-url https://controlplane.example.com:7443 \
  --policy examples/obpee-cp-policy.json \
  > obpee-cp-oidc.json
```

The output contains a `secretRefs.providerClientSecret` reference, never a
client-secret value. `request` is the Control Plane API-shaped portion; a future
supported API apply path must resolve the reference only in memory.

For OBP after selecting your OCI context and importing an `oci-context` token
service, the shortest planning command is:

```bash
oci-context use oabcs1

oci-idm plan apps \
  --service obp \
  --resource-app-id example-resource-app-id \
  --base-app-name example-obp_APPID \
  --include user,jwt-service \
  --role-preset obp-admin \
  --app-role-grants ADMIN=example-admin-role-id,REST_CLIENT=example-rest-client-role-id \
  --principal-mode auto \
  --principal-email-domain example.invalid \
  -o json > idm-plan.json
```

Discover the service-created resource app:

```bash
oci-idm get service-apps \
  --query example-oabcs \
  -o text
```

Inspect the resource app once you know its id:

```bash
oci-idm describe service-app \
  --app-id example-resource-app-id \
  -o text
```

Resource apps can have `allowOffline: false`, which causes Identity Domains to
reject Authorization Code requests containing `offline_access`. Add only the
missing redirect URI and grant types, alongside offline access when needed:

```bash
oci-idm patch app \
  --app-id example-resource-app-id \
  --allow-offline \
  --add-redirect-uri http://127.0.0.1:8180/callback \
  --add-grant authorization_code \
  --add-grant refresh_token \
  --confirm
```

The command reads issuer, OCI profile, config path, and region from the current
`oci-context` by default. It reads the live app, adds no duplicate values, and
verifies the result after a successful patch. `--execute` remains a no-op
compatibility flag; `--confirm` is the only mutation gate.

## Web-app role assignments

Assign an approved Identity Domains user or group to an application role without
maintaining a separate desired-state file. The command searches for the exact
grant first, creates it only if missing, and verifies it afterward:

```bash
oci-idm assign app-role \
  --app-id example-web-app-id \
  --role-id example-web-app-role-id \
  --group-id approved-web-app-group-id \
  --confirm
```

Use `--user-id` instead of `--group-id` for a direct user grant. For the
person represented by the current `oci-context` token, resolve the exact
Identity Domains user ID first and keep the assignment target explicit in the
result:

```bash
oci-idm assign app-role \
  --app-id example-web-app-id \
  --role-id example-web-app-role-id \
  --me \
  --oci-context-service example-service \
  --confirm
```

`--me` is an alias for `--current-user`. It requires issuer-matched, unexpired subject metadata from
`oci-context auth subject`, then looks up an exact Identity Domains user ID
before creating the grant. IDs are intentional: they make the target
unambiguous and preserve review boundaries. This configures Identity Domain
app access only; it does not change Control Plane OIDC provider configuration
or Kubernetes resources.

Omit `--confirm` to inspect the same exact grant first. The command returns
`already-assigned` when present or a non-mutating `planned` result when the
grant is missing; add `--confirm` only to create it.

Oracle service apps can protect seeded attributes even when the generic App
schema describes them as writable. When `isOPCService` is true and
`editableAttributes` does not contain `allowOffline`, `oci-idm` refuses the
patch before making a change and identifies the Oracle service type. The
service owner or Oracle Support must enable refresh for that resource app. A
customer-owned resource app cannot duplicate the same fully qualified scope,
because scope FQS values are unique within an identity domain.

Diagnose a generated client app against a known-good app:

```bash
oci-idm diagnose apps \
  --service obp \
  --resource-app-id example-resource-app-id \
  --candidate-app-id generated-client-app-id \
  --known-good-app-id known-working-client-app-id \
  -o text
```

The diagnostic output checks both sides of refresh eligibility. The client app
must allow Authorization Code and Refresh Token grants, while the target
resource app must have `allowOffline: true`. A client-side `refresh_token`
grant alone cannot make a protected Oracle service app issue refresh tokens.
The generated inspection commands include `isOPCService` and
`editableAttributes` so this limitation is visible before a patch is tried.

Plan companion apps and service role grants:

```bash
oci-idm plan apps \
  --service obp \
  --issuer https://idcs-example.identity.oraclecloud.com \
  --platform https://example-oabcs.blockchain.ocp.oraclecloud.com:7443/restproxy \
  --resource-app-id example-resource-app-id \
  --base-app-name example-obp_APPID \
  --include user,jwt-service \
  --role-preset obp-admin \
  --app-role-grants ADMIN=example-admin-role-id,REST_CLIENT=example-rest-client-role-id \
  --principal-mode auto \
  --principal-email-domain example.invalid \
  -o json > idm-plan.json
```

Materialize reviewed payloads and helper scripts:

```bash
oci-idm materialize plan -f idm-plan.json --out ./idm-artifacts
```

The output directory contains:

- `plan.json`
- OCI Identity Domains payload JSON files
- `apply.sh`
- `validate.sh`
- `cleanup.sh`
- `oci-context.handoff.json`
- `oci-context-token-services.yml`
- `oci-context-token-commands.sh`

Run a local readiness report over the current `oci-context` defaults and a
plan:

```bash
oci-idm doctor plan -f idm-plan.json -o text
```

Plan-consuming commands also accept `-f -`, so checks can be composed
without temporary plan files:

```bash
oci-idm plan apps --service obp --resource-app-id example-resource-app-id |
  oci-idm doctor plan -f - -o text
```

## Pipe Outputs

For day-to-day shell use, prefer emitting the needed projection directly from
`plan` and piping it to the next tool.

Create or select a CLI-capable auth target from the current `oci-context`
service and make it current for later `oci-context` commands:

```bash
oci-context use oabcs1

oci-idm clone app --flow authorization-code --name hebe-obp-user |
  oci-context service add --set-current

oci-context auth login
oci-context auth token --no-login --format raw
```

`clone app` emits a standard `oci-context` handoff document by default. It does
not print secrets. Use the existing `plan apps`, `materialize plan`, and
`apply plan --confirm` path when you need reviewable payload files and
live Identity Domains creation. Authorization-code handoffs include
`offlineAccess: true`, so `oci-context` requests `offline_access` and can cache
the refresh token enabled by the generated app.

Login to the current OBP target through `oci-context`:

```bash
oci-idm get defaults --service obp |
  oci-context auth login

oci-context auth token --service obp --no-login --format raw
```

`get defaults` emits the current `oci-context` name, OCI profile, region,
token-service name, issuer, and scope. `oci-context auth login` consumes that
target metadata, merges the non-secret service values into the matching token
service, and runs the interactive Authorization Code or Device Code login
configured for that service.

After that metadata is in an `oci-context` file with `current_service` set, the
short form is enough:

```bash
oci-context auth login
oci-context auth token --no-login --format raw
```

Import generated `oci-context` token services:

```bash
oci-idm plan apps --service obp --resource-app-id example-resource-app-id \
  -o oci-context-yaml |
  oci-context service add --set-current
```

Merge the generated `token_services` entries into a global or project
`oci-context` config, then validate with `oci-context auth token`.

Emit OChain environment data in standard shell, dotenv, or JSON shapes:

```bash
# Source a POSIX shell export.
eval "$(oci-idm plan apps --service obp --resource-app-id example-resource-app-id \
  -o ochain-env)"

# Write a dotenv fragment for tools that load .env files.
oci-idm plan apps --service obp --resource-app-id example-resource-app-id \
  -o ochain-dotenv > .env.ochain

# Pass JSON to another program without shell evaluation.
oci-idm plan apps --service obp --resource-app-id example-resource-app-id \
  -o ochain-json
```

OChain outputs write an `OCHAIN_TOKEN_COMMAND` value using the generated
`oci-context` token service. By default they choose the first non-browser token
service, such as `obp-jwt-service`; pass `--token-service obp` when you want a
cached authorization-code user token instead.

For saved plan files and older scripts, `handoff` remains available as a
compatibility filter:

```bash
oci-idm handoff -f idm-plan.json --target oci-context -o yaml
```

For a planned OBP authorization-code app:

```bash
oci-idm get defaults --service obp |
  oci-context auth login
```

For a planned OBP JWT service app:

```bash
export EXAMPLE_OBP_SERVICE_JWT_PRIVATE_KEY_FILE=./example-obp-service-jwt.key

oci-context auth token \
  --service obp-jwt-service \
  --flow jwt-client-credentials \
  --no-login \
  --format raw
```

For OCI Identity Domains JWT client assertion, the generated handoff sets
`jwt_audience: https://identity.oraclecloud.com/`. Current `oci-context`
versions also retry that audience automatically when an OCI Identity Domain
rejects the generic token-endpoint audience.

## Role Presets

The built-in OBP role presets are:

- `obp-admin`: `ADMIN` and `REST_CLIENT`
- `obp-rest-client`: `REST_CLIENT`
- `obp-user`: `USER`
- `obp-ca-user`: `CA_USER`

Use `--app-role-grants NAME=APP_ROLE_ID` to provide custom grants or override
preset placeholders.

## Service Principals

Some Oracle cloud services do not authorize a service-account token only by
checking the OAuth client app's granted roles. Instead, the target service reads
the access-token subject, resolves that subject as an OCI Identity Domains user,
and then checks the user's service application roles.

For client-credentials flows, OCI Identity Domains commonly sets the token
subject to the OAuth client id. For those services, the required pattern is:

- create the OAuth client app
- create or reuse a user whose `userName` exactly matches the OAuth client id
- grant service application roles to that user with `ADMINISTRATOR_TO_USER`
- mint the token with the OAuth client, then validate the target service call

`oci-idm` models this with `--principal-mode`:

- `auto`: default; enables `same-name-user` for known services such as OBP and
  otherwise resolves to `none`
- `none`: create app resources and app-role grants only
- `same-name-user`: also create a same-name principal user and user-role grants

OCI Identity Domains requires a primary email for users. By default, generated
principal users use `<client-id>@example.invalid`. Set
`--principal-email-domain` to an approved internal domain or edit the
materialized `*-principal-user.json` payload before applying it.

For a generic service that uses this subject-to-user authorization pattern:

```bash
oci-idm plan apps \
  --service generic \
  --issuer https://idcs-example.identity.oraclecloud.com \
  --scope https://service.example.com/.default \
  --resource-app-id service-resource-app-id \
  --include jwt-service \
  --principal-mode same-name-user \
  --principal-email-domain svc.example.com \
  --app-role-grants SERVICE_ADMIN=service-admin-role-id \
  -o json > idm-plan.json
```

For OBP/OBPCS REST proxy OAuth, Oracle documents that client-credentials tokens
use the client id as the token subject. OBP then looks up application roles for
that subject as a user. See Oracle's OBP OAuth authentication documentation:
<https://docs.oracle.com/en/cloud/paas/blockchain-cloud/restoci/UseOAuth.html>.
This is why OBP service-account plans use `same-name-user` in `auto` mode.

## Diagnosis

`oci-idm diagnose apps` emits safe OCI CLI commands for comparing a service/resource
app, a candidate OAuth client app, and an optional known-good client app. It
checks the surfaces that matter for CLI and automation handoff:

- service app metadata and app-role projections
- direct `Grant` resources for the candidate and known-good app
- `granted-app-roles` projected onto the candidate app
- same-name user lookup for services that resolve token subjects as users
- user `Grant` resources for the candidate and known-good principal user
- `AccountMgmtInfo` rows for the service/resource app

For OBP/OBPCS, a token can mint successfully and the candidate app can show the
expected app-side `granted-app-roles`, while OBPCS still returns
`OBP_ADMIN_FORBIDDEN` with `Failed to get application role for user`. In that
case, check whether a same-name user exists and has `ADMINISTRATOR_TO_USER`
grants for the OBP `ADMIN` and `REST_CLIENT` app roles.

## Apply Model

Use `materialize plan` for local review artifacts:

```bash
oci-idm materialize plan -f idm-plan.json --out ./idm-artifacts
```

For reviewed plans, `apply plan --confirm` runs the OCI Identity Domains changes
directly. The executor is intentionally conservative:

- it searches for existing apps by name before creating them
- it searches for existing same-name principal users before creating them
- it resolves created or reused app/user ids before creating grants
- it searches for existing matching grants before creating new grants
- it fails closed when generated payloads still contain placeholders

```bash
oci-idm apply plan \
  -f idm-plan.json \
  --out ./idm-apply \
  --confirm \
  -o text
```

JWT service plans still need real certificate material before direct execution.
Materialize first, replace placeholders such as
`<x509-base64-der-certificate>` and preset role ids, then rerun direct apply.
`--execute` remains a no-op compatibility flag and can be removed from scripts.

## Compatibility

The old command name continues to work:

```bash
oci-identity-apps version
oci-identity-apps plan apps --issuer ... --scope ...
```

New documentation and package names use `oci-idm`.
