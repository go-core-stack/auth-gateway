# Auth Gateway

[![Nightly Image Build](https://github.com/go-core-stack/auth-gateway/actions/workflows/nightly-build.yml/badge.svg)](https://github.com/go-core-stack/auth-gateway/actions/workflows/nightly-build.yml)

This repo provides construct to manage Tenants with hard and soft tenancy
definitions to work with. Eventually this repo is also supposed to be offering
options to work as both Authentication and Authorization Gateway for all the
hosted services made available via the auth gateway

Following is the standard mapping of various types of multi tenancy capabilities
and resources supported in auth gateways

![Tenant & Org Unit Mapping](docs/img/tenant-org-units.png "Tenant & Org Unit Mapping")

## Customer / Tenant / Org Unit / User Associations

### Concept Overview
- **Customer** — Billing entity for the overall platform. Customers onboard with
  either a dedicated tenancy (current default) or, in the future, a shared
  tenancy similar to GitHub’s org model where invitations are required and auth
  features remain centrally managed. Dedicated tenancies expose the full
  authentication surface, provide a customer-specific subdomain or custom
  domain, and are expected to serve business customers, whereas individuals are
  typically routed toward the forthcoming shared mode. Onboarding captures
  regulatory and fiscal identifiers (PAN / TAN / GST), address, contact details,
  and verification artifacts; individuals must clear KYC while businesses
  complete KYB. The customer API currently returns only the built-in root
  record flagged as dedicated, reflecting the bootstrap state of the service.
  Every customer is created with a non-deletable “break glass” admin user that
  can later be disabled if the tenant provides alternate operational paths.
- **Tenant** — Logical security and management boundary mapped to a Keycloak
  realm. Dedicated customers automatically receive a tenant at onboarding;
  future shared customers will attach to a pre-provisioned shared cloud tenant.
  Tenant metadata captures display details, default admin credentials, and
  runtime provisioning status for the realm, auth client, and role sync. Service
  startup guarantees that the bootstrap root tenant and its default admin
  account are present. Each tenant ultimately maps to a branded login surface
  (`customer1.example.com`, custom domains, `console.example.com` for internal
  ops, `cloud.example.com` for public shared access).
- **Org Unit (OU)** — Customer-controlled resource grouping. Org unit records
  store an identifier, human-readable metadata, and the owning tenant. Org unit
  APIs let tenant administrators create, list, and update OUs inside their
  realm.
- **User** — End user identity scoped to a tenant. User records are keyed by
  tenant and username, capture profile data, and track provisioning state. Both
  admin-facing and tenant-scoped APIs offer CRUD plus enable/disable flows.

### How the Pieces Connect
1. **Customer ➜ Tenant**
   - Every billable customer eventually maps to one or more tenants. For
     dedicated customers, onboarding creates an isolated tenant and realm so the
     customer can manage identities, SSO, and security controls without sharing
     space with other customers.
   - The current schema does not persist an explicit customer identifier on
     tenant records; the bootstrap path simply wires the singleton root customer
     to the root tenant. Future onboarding must extend tenant storage
     so billing ownership can be traced programmatically.

2. **Tenant ➜ Keycloak Realm**
   - A tenant setup controller watches tenant records. When it encounters a
     tenant whose Keycloak status is unset, it provisions or updates a realm
     named after the tenant key, ensures a controller client exists with the
     correct protocol mappers, and records the provisioning timestamps.
   - This linkage ensures that tenant creation in the datastore automatically
     drives identity infrastructure setup for dedicated customers.

3. **Tenant ➜ Org Unit**
   - Each org unit carries its owning tenant. All org unit APIs resolve the
     caller’s tenant from the auth context and constrain reads and writes to
     that tenant boundary.
   - Because org units sit under a tenant, billing systems can attribute
     resource usage per org unit while remaining within the customer’s isolated
     realm.

4. **Tenant ➜ User**
   - User keys are tenant-scoped. Both the tenant-level and “my tenant” APIs
     filter on the active realm before listing or mutating accounts.
   - Default tenant admins are created from bootstrap configuration during
     startup. Subsequent admins can enable, disable, and update users, and the
     disable operation flips a user-level flag respected by downstream auth
     flows.

5. **Org Unit ⇄ User**
   - Membership uses a composite key of tenant, username, and org unit
     identifier. Tenant administrators can attach users to org units with scoped
     roles such as admin, default, or auditor. Lookups and mutations are
     tenant-aware to prevent cross-tenant leakage.

### Operational Considerations
- **KYC / KYB** — Regulatory checks are currently handled outside the Auth
  Gateway. Individuals require KYC, businesses require KYB, and supporting
  identifiers (PAN / TAN / GST) plus contact metadata must be captured before
  feature access. A superadmin (root customer / root tenant) updates each
  customer’s status manually (pending, completed, partial, due for re-KYC). Once
  that status is stored in an external system, the gateway can react (for
  example, by blocking tenant creation or user logins) by consulting the
  external status before servicing customer-specific requests.
- **Payments & Access Control** — Payment status is also sourced externally.
  When a customer falls behind on payments, the external billing process should
  call back into admin APIs to disable the affected tenant or users. Today that
  means toggling the user-level disable flag through the tenant user management
  API or, once implemented, a tenant-wide disable switch. Re-enabling access
  follows the inverse flow after the billing system marks the account as
  settled.

### Gaps & Next Steps
- Extend tenant records with an explicit customer reference so the runtime
  association is explicit.
- Introduce tenant-level status fields (for example, KYC state or payment
  standing) to replace manual tracking and allow enforcement at request entry
  points.
- Expand customer APIs beyond the bootstrap stub to create, read, and update
  real records, driving automated tenant provisioning for dedicated customers
  and configurable sharing for shared tenants.
