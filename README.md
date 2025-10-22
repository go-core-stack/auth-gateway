# Auth Gateway

[![Nightly Image Build](https://github.com/go-core-stack/auth-gateway/actions/workflows/nightly-build.yml/badge.svg)](https://github.com/go-core-stack/auth-gateway/actions/workflows/nightly-build.yml)

This repo provides construct to manage Tenants with hard and soft tenancy
definitions to work with. Eventually this repo is also supposed to be offering
options to work as both Authentication and Authorization Gateway for all the
hosted services made available via the auth gateway

Following is the standard mapping of various types of multi tenancy
capabilities and resources supported in auth gateways

![Tenant & Org Unit Mapping](docs/img/tenant-org-units.png "Tenant & Org Unit Mapping")

## Customer / Tenant / Org Unit / User Associations

### Concept Overview
- **Customer** — Billing entity for the overall platform. Customers can operate in dedicated or shared tenancy modes. The gRPC surface in `pkg/server/customer.go` and `api/customer.proto` exposes CRUD endpoints, but the current implementation only returns the built-in `root` customer and marks it as `Dedicated`, reflecting the bootstrap state of the service.
- **Tenant** — Logical security and management boundary mapped to a Keycloak realm. `table.TenantEntry` (see `pkg/table/tenant.go`) captures display metadata, the default tenant admin credential, and runtime statuses (Keycloak provisioning, auth client, role sync). `main.go` guarantees that the bootstrap `root` tenant and its default admin account are present at startup via `locateRootTenant`.
- **Org Unit (OU)** — Customer-controlled resource grouping. `table.OrgUnitEntry` (defined in `pkg/table/org-unit.go`) stores an OU identifier, human-readable metadata, and the owning tenant. The `OrgUnitServer` (`pkg/server/org-unit.go`) lets tenant administrators create, list, and update OUs inside their realm.
- **User** — End user identity scoped to a tenant. `table.UserEntry` (`pkg/table/user.go`) keys each record by `<tenant, username>`, records profile info, and tracks provisioning state. `TenantUserApiServer` and `UserApiServer` in `pkg/server/tenant-user.go` and `pkg/server/user.go` provide admin-facing and tenant-scoped CRUD plus enable/disable flows.

### How the Pieces Connect
1. **Customer ➜ Tenant**
   - Every billable customer eventually maps to one or more tenants. For dedicated customers, onboarding creates an isolated tenant/realm so the customer can manage identities, SSO, and security controls without sharing space with other customers.
   - The codebase does not yet persist an explicit `customerId` inside `table.TenantEntry`; the bootstrap path simply wires the singleton `root` customer to the `root` tenant. Future customer onboarding must extend the tenant schema (for example, by adding a `Customer` field) so billing ownership can be traced programmatically.

2. **Tenant ➜ Keycloak Realm**
   - `tenant.SetupController` (`pkg/controller/tenant/setup.go`) watches tenant records. When it encounters a tenant whose Keycloak status is unset, it provisions or updates a realm named after `TenantKey.Name`, ensures a `controller` client exists with the correct protocol mappers, and stamps the `TenantEntry.KCStatus` / `AuthClient` timestamps.
   - This linkage ensures that tenant creation in the datastore automatically drives identity infrastructure setup for dedicated customers.

3. **Tenant ➜ Org Unit**
   - Each `OrgUnitEntry` carries its owning tenant (`OrgUnitEntry.Tenant`). All Org Unit APIs resolve the caller’s tenant from the auth context (`auth.GetAuthInfoFromContext`) and constrain reads/writes to that tenant (`pkg/server/org-unit.go:27-112`).
   - Because Org Units sit under a tenant, billing systems can attribute resource usage per OU while remaining within the customer’s isolated realm.

4. **Tenant ➜ User**
   - User keys are tenant-scoped (`table.UserKey.Tenant`). Both the tenant-level and “my tenant” APIs filter on the active realm before listing or mutating users (`pkg/server/user.go:64-138`, `pkg/server/tenant-user.go:62-149`).
   - Default tenant admins are created from `TenantConfig.DefaultAdmin` as part of `locateRootTenant` (`main.go:70-127`). Subsequent admins can enable, disable, and update users. Disable operations flip the `UserEntry.Disabled` flag, which downstream auth flows respect.

5. **Org Unit ⇄ User**
   - Membership is stored in `table.OrgUnitUser` (`pkg/table/org-unit-user.go`) with a composite key `<tenant, username, orgUnitId>`. `OrgUnitUserServer` (`pkg/server/org-unit-user.go`) allows tenant admins to attach users to Org Units with scoped roles (`admin`, `default`, `auditor`). Lookups and mutations are tenant-aware to prevent cross-tenant leakage.

### Operational Considerations
- **KYC / KYB** — Regulatory checks are currently handled outside the Auth Gateway. A superadmin (root customer / root tenant) updates each customer’s status manually (pending, completed, partial, due for re-KYC). Once that status is stored in an external system, the gateway can react (for example, by blocking tenant creation or user logins) by consulting the external status before servicing customer-specific requests.
- **Payments & Access Control** — Payment status is also sourced externally. When a customer falls behind on payments, the external billing process should call back into admin APIs to disable the affected tenant or users. Today that means toggling the `UserEntry.Disabled` flag via `TenantUserApiServer.DisableUser` (`pkg/server/tenant-user.go:150-185`) or, once implemented, a tenant-level disable flag. Re-enabling access follows the inverse flow after the billing system marks the account as settled.

### Gaps & Next Steps
- Persist a `Customer` reference inside `table.TenantEntry` so the runtime association is explicit.
- Introduce tenant-level status fields (e.g., `kycStatus`, `paymentStatus`) to replace manual tracking and allow enforcement at request entry points.
- Extend customer APIs beyond the bootstrap stub in `pkg/server/customer.go` to create/read/update real records, driving automated tenant provisioning for dedicated customers and configurable sharing for shared tenants.