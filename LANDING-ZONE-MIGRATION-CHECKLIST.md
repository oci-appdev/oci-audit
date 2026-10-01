# OCI Old-to-New Landing Zone Migration Checklist

**Purpose:** Controlled migration of OCI resources from legacy compartments / legacy landing-zone resources (especially the 172.16.0.0/16 network) into the new landing-zone compartment structure and 10.0.0.0/8 network.

**Last reviewed:** 2026-10-01

**Repository integration:** This checklist is designed to be used with `python-sdk/environment-gap-analysis/oci-network-gap-analysis.py`.

> **Critical distinction:** Moving a resource to another compartment changes governance/ownership scope. It does **not** necessarily migrate that resource to the new landing-zone network. A VCN compartment move keeps its CIDR/routing, and a Compute instance compartment move does not move its boot volume or VNIC. Any workload that must leave the legacy 172.16 network and operate on the new 10.x network must have a separate network migration/cutover plan.

---

## 1. Migration Status Model

Use exactly one migration disposition for every discovered resource.

| Disposition | Meaning |
|---|---|
| **MOVE** | Resource can remain technically unchanged and only needs compartment reassignment. |
| **MIGRATE / REBUILD** | Resource must be recreated, restored, re-IPed, reattached, or otherwise moved onto the new 10.x landing-zone network. |
| **KEEP-SHARED** | Shared service remains in place and is intentionally consumed by both old and new environments during transition. |
| **HOLD** | Dependency, owner, backup, security, legal/retention, IaC, or change-control question is unresolved. |
| **DECOMMISSION-CANDIDATE** | Resource is no longer required, has no unresolved dependencies, has passed retention/backup/change gates, and is ready for authorized removal review. |
| **DECOMMISSIONED** | Destructive action was separately approved, executed, and evidenced. |

**Never treat DECOMMISSION-CANDIDATE as deletion authorization.**

---

## 2. Mandatory Migration Register

Create one row for every resource found by the gap-analysis collector or manual review.

- [ ] Resource type
- [ ] Display name
- [ ] Resource OCID
- [ ] Region
- [ ] Availability Domain / Fault Domain if applicable
- [ ] Source compartment OCID
- [ ] Source parent / old landing-zone compartment
- [ ] Target compartment OCID
- [ ] Creation date
- [ ] Legacy CIDR dependency: 172.16.x.x / none / unknown
- [ ] Current private IP / public IP if applicable
- [ ] Target 10.x subnet / IP requirement if applicable
- [ ] Resource owner
- [ ] Application owner
- [ ] Security owner
- [ ] Migration disposition
- [ ] Migration method
- [ ] Upstream dependencies
- [ ] Downstream dependencies
- [ ] DNS dependencies
- [ ] IAM / Dynamic Group dependencies
- [ ] KMS / Vault dependencies
- [ ] Logging / alarm dependencies
- [ ] Backup / recovery requirement
- [ ] Terraform / CD3 / Resource Manager state reference
- [ ] Change ticket / CRQ
- [ ] Maintenance window
- [ ] Rollback method
- [ ] Validation evidence
- [ ] Final status

---

# PHASE 0 — Discovery and Freeze

## 0.1 Run the Existing Gap Analysis

- [ ] Run `python-sdk/environment-gap-analysis/oci-network-gap-analysis.py` against the tenancy or approved old landing-zone root compartments.
- [ ] Use the default old-resource cutoff unless the migration authority approves another date.
- [ ] Confirm old CIDR boundary includes `172.16.0.0/16`.
- [ ] Confirm new landing-zone CIDR boundary includes the approved `10.0.0.0/8` ranges.
- [ ] Repeat the inventory in every OCI region containing candidate resources.
- [ ] Resolve all SDK collection errors before authorizing any decommission decision.
- [ ] Resolve all unknown-compartment and cross-compartment references.
- [ ] Export and retain the complete resource inventory, dependency graph, coverage ledger, and error ledger.
- [ ] Identify resources created before 2026 that are still attached to 172.16 networks.
- [ ] Identify resources under confirmed old landing-zone compartments even if they are not attached to 172.16.
- [ ] Identify shared resources referenced by both old and new environments.
- [ ] Identify resources managed by Terraform/CD3/Resource Manager.

## 0.2 Establish a Change Freeze

- [ ] Freeze nonessential changes in the old environment during final dependency mapping.
- [ ] Record approved exceptions to the freeze.
- [ ] Prevent new workloads from being created in old compartments.
- [ ] Prevent new workloads from using 172.16 subnets unless explicitly approved.
- [ ] Record the final migration inventory snapshot/hash before cutover begins.

### Gate 0 — Discovery Complete

Proceed only when:

- [ ] All in-scope regions have been scanned.
- [ ] No unresolved scan failures affect candidate resources.
- [ ] Every resource has an owner or an approved orphan-resource disposition.
- [ ] Every resource has a target disposition.
- [ ] IaC-managed resources are identified.
- [ ] Old-network dependencies are explicitly mapped.

---

# PHASE 1 — Validate the New Landing Zone

## 1.1 Compartment Structure

- [ ] Confirm target network compartment.
- [ ] Confirm target application compartments.
- [ ] Confirm target database compartments.
- [ ] Confirm target shared-services compartment.
- [ ] Confirm target logging/security compartment.
- [ ] Confirm backup / DR compartments if used.
- [ ] Confirm naming standards.
- [ ] Confirm defined-tag namespaces and mandatory tags.
- [ ] Confirm tag defaults.
- [ ] Confirm quotas and service limits.
- [ ] Confirm security-zone membership and restrictions.

## 1.2 IAM / Identity / Policy

- [ ] Review all policies that currently reference old compartment names or OCIDs.
- [ ] Create or update policies for target compartments before the move.
- [ ] Confirm administrators retain access after each resource move.
- [ ] Confirm application groups retain required use/read/manage permissions.
- [ ] Review Dynamic Groups for rules referencing old compartment OCIDs.
- [ ] Review Instance Principal permissions.
- [ ] Review Resource Principal permissions for Functions and other services.
- [ ] Review service policies such as Object Storage, KMS, Logging, ONS, Streaming, Service Connector Hub, and Vault.
- [ ] Confirm break-glass access works in the new landing zone.
- [ ] Verify policy-object count remains below tenancy limits.
- [ ] Prefer policies scoped to appropriate child compartments instead of unnecessary root-level policy objects.

## 1.3 Security / Encryption

- [ ] Confirm target Vault/KMS keys.
- [ ] Confirm key policies allow target workloads to use required keys.
- [ ] Confirm security-zone rules will not block planned moves.
- [ ] Confirm NSGs and security lists follow approved ports/protocols/services.
- [ ] Confirm TLS certificates and certificate chains.
- [ ] Confirm secrets/config values are available without exporting secret material into migration evidence.
- [ ] Confirm Cloud Guard / security monitoring expectations.

### Gate 1 — Target Governance Ready

- [ ] Target compartments exist.
- [ ] Required IAM policies are active.
- [ ] Security controls are active.
- [ ] Required KMS/Vault access is tested.
- [ ] Operators can manage resources in both source and destination during migration.

---

# PHASE 2 — Build and Validate the New 10.x Network

> Do **not** satisfy the network migration by simply moving the old 172.16 VCN into a new compartment. A VCN move preserves the network itself.

## 2.1 VCN and Subnets

- [ ] Confirm new VCN CIDRs.
- [ ] Confirm there is no overlap with on-premises, FastConnect, VPN, peered VCNs, DR regions, or partner networks.
- [ ] Create/validate application subnets.
- [ ] Create/validate database subnets.
- [ ] Create/validate load-balancer subnets.
- [ ] Create/validate OKE worker/pod/API endpoint subnets if applicable.
- [ ] Create/validate File Storage mount-target subnets.
- [ ] Create/validate management / jumpbox subnet.
- [ ] Confirm private/public subnet intent.
- [ ] Confirm DNS resolver configuration.
- [ ] Confirm DHCP options.
- [ ] Confirm route tables.
- [ ] Confirm NSGs.
- [ ] Confirm security lists where still used.

## 2.2 Gateways

- [ ] Internet Gateway only where approved.
- [ ] NAT Gateway for approved outbound private-subnet access.
- [ ] Service Gateway for OCI service access where required.
- [ ] DRG attachment to the new VCN.
- [ ] Local/remote peering only where architecture requires it.

## 2.3 DRG / FastConnect / On-Premises Routing

If the existing DRG is already connected to FastConnect, the preferred transition is generally to attach the new VCN to that DRG and validate routing rather than recreating FastConnect unnecessarily.

- [ ] Create/validate new VCN-to-DRG attachment.
- [ ] Confirm DRG route table association.
- [ ] Confirm DRG import route distribution.
- [ ] Confirm on-premises routes to the new 10.x CIDRs.
- [ ] Confirm new 10.x VCN routes back to on-premises.
- [ ] Confirm BGP advertisements.
- [ ] Confirm firewall rules on-premises.
- [ ] Confirm OCI NSG/security-list rules.
- [ ] Confirm asymmetric routing is not introduced.
- [ ] Confirm return routes for every migrated subnet.
- [ ] Test ICMP only where permitted.
- [ ] Test TCP application ports from jumpbox/on-premises.
- [ ] Test SSH/RDP from approved administration sources.
- [ ] Test DNS resolution in both directions if required.

## 2.4 DNS

- [ ] Inventory private DNS zones and views.
- [ ] Inventory public DNS records.
- [ ] Reduce TTL before major application cutovers when appropriate.
- [ ] Prepare new 10.x records.
- [ ] Validate resolver rules and forwarding.
- [ ] Validate on-premises DNS forwarders.
- [ ] Do not switch production records until workload validation passes.

### Gate 2 — New Network Ready

- [ ] New 10.x subnets are reachable as designed.
- [ ] FastConnect/VPN/on-premises routing works.
- [ ] DNS works.
- [ ] Required ports work.
- [ ] Security controls are validated.
- [ ] No production cutover yet.

---

# PHASE 3 — Shared Infrastructure and Storage

## 3.1 Object Storage

A bucket can be moved between compartments, but destination policies immediately apply.

- [ ] Record bucket name, namespace, OCID, lifecycle policy, retention configuration, replication, versioning, PAR dependencies, and KMS key.
- [ ] Confirm destination compartment permissions.
- [ ] Confirm retention/immutability requirements.
- [ ] Confirm Service Connector / Logging / FinOps integrations.
- [ ] Move bucket only when governance relocation is sufficient.
- [ ] If applications use private Service Gateway paths, validate access from the new VCN.
- [ ] Retest all SDK/API clients after move.
- [ ] Retest PAR-based workflows if applicable.
- [ ] Confirm audit/log exports still arrive.

## 3.2 Block Volumes / Boot Volumes / Backups

Compute-resource moves do not automatically move boot volumes or VNICs.

- [ ] Inventory boot volume for every VM.
- [ ] Inventory attached block volumes.
- [ ] Inventory volume groups.
- [ ] Inventory volume backups.
- [ ] Inventory boot-volume backups.
- [ ] Inventory cross-region replicas.
- [ ] Confirm KMS keys.
- [ ] Confirm backup-policy assignments.
- [ ] Move volumes separately when compartment alignment is required.
- [ ] Remember that moving a volume does not automatically move its backups/clones/replicas.
- [ ] Validate attachments after each move.
- [ ] Validate backup jobs after each move.
- [ ] Validate alarm compartment references.

## 3.3 File Storage

- [ ] Inventory file systems.
- [ ] Inventory snapshots.
- [ ] Inventory mount targets.
- [ ] Inventory export sets/exports.
- [ ] Inventory mount IPs used by application hosts.
- [ ] Inventory `/etc/fstab` and application configuration references.
- [ ] If only changing compartment, move file system/mount target as supported.
- [ ] If moving to the new 10.x subnet, create a new mount target in the target subnet.
- [ ] Recreate the export using the same export path.
- [ ] Stop application writes for cutover.
- [ ] Unmount old target.
- [ ] Mount through the new 10.x mount target.
- [ ] Update `/etc/fstab` / automount / application configuration.
- [ ] Validate read/write and permissions.
- [ ] Remove old mount target only after validation.

### Gate 3 — Shared Storage Ready

- [ ] Backups exist and restore procedures are known.
- [ ] Shared file/object/block storage is reachable from new networks.
- [ ] KMS access works.
- [ ] No old storage endpoint is removed yet.

---

# PHASE 4 — Databases

> Moving a database resource into a new compartment does not, by itself, prove that the database is using the new 10.x landing-zone network.

## 4.1 Database Inventory

- [ ] Base Database Service DB Systems
- [ ] RAC / VM DB Systems
- [ ] Exadata Cloud VM Clusters
- [ ] Autonomous Databases
- [ ] Autonomous Container Databases / dedicated infrastructure if applicable
- [ ] MySQL HeatWave
- [ ] OCI Database with PostgreSQL
- [ ] DB backups
- [ ] Data Guard / standby relationships
- [ ] Database private endpoints
- [ ] SCAN/listener endpoints
- [ ] DNS aliases
- [ ] Wallets/certificates
- [ ] KMS keys
- [ ] Monitoring/alarm rules
- [ ] Application connection strings

## 4.2 Choose the Correct Database Migration Method

### Compartment-only move

Use only when the current network placement remains acceptable.

- [ ] Confirm service supports Change Compartment for the exact DB resource type.
- [ ] Confirm which dependent resources move with the DB system.
- [ ] Confirm destination policies first.
- [ ] Move resource.
- [ ] Validate DB lifecycle state.
- [ ] Validate backups.
- [ ] Validate monitoring.
- [ ] Validate application connections.

### New 10.x network migration

When the database must leave the legacy 172.16 VCN/subnet:

- [ ] Select approved migration method: backup/restore, Data Guard, RMAN, Data Pump, GoldenGate, service-native replica/restore, or other approved database migration method.
- [ ] Provision target database in the new 10.x DB subnet.
- [ ] Match encryption requirements.
- [ ] Match parameter/configuration requirements.
- [ ] Restore/synchronize data.
- [ ] Validate schema/object counts.
- [ ] Validate users/roles without exposing credentials.
- [ ] Validate jobs/schedulers.
- [ ] Validate backup configuration.
- [ ] Validate HA/standby configuration.
- [ ] Validate performance baseline.
- [ ] Freeze writes or execute final synchronization.
- [ ] Cut application connection strings / DNS.
- [ ] Validate transactions.
- [ ] Keep source database intact for the approved rollback window.
- [ ] Decommission only under separate approval after retention requirements are satisfied.

### Gate 4 — Database Ready

- [ ] Target database is healthy.
- [ ] Data consistency is validated.
- [ ] Application connectivity from 10.x is proven.
- [ ] Backups are successful.
- [ ] Rollback remains available.

---

# PHASE 5 — Compute / Virtual Machines

## 5.1 Compartment-Only VM Move

Oracle supports moving an instance between compartments, but associated boot volumes and VNICs are not moved automatically.

- [ ] Confirm destination IAM.
- [ ] Confirm security-zone compatibility.
- [ ] Move instance.
- [ ] Move boot volume separately if required by target governance.
- [ ] Move attached block volumes separately if required.
- [ ] Review VNIC/private-IP compartment behavior.
- [ ] Update alarms to the new metric compartment.
- [ ] Confirm backup-policy access.
- [ ] Confirm Instance Principal / Dynamic Group rules.
- [ ] Confirm OS Management / vulnerability scanning access.
- [ ] Confirm Bastion/SSH/RDP access.

## 5.2 VM Migration from 172.16 to 10.x

For a clean landing-zone migration, treat a VM's primary-network change as a rebuild/migration, not a compartment-only operation.

- [ ] Confirm source VM is migration-ready.
- [ ] Confirm current OS and patch level.
- [ ] Confirm source VM uses DHCP on primary NIC where required by migration design.
- [ ] Remove hard-coded old static IP/gateway configuration before image-based migration when applicable.
- [ ] Remove or correct old NTP configuration.
- [ ] Remove boot-blocking NFS/on-premises dependencies.
- [ ] Confirm the VM can boot without old-environment dependencies.
- [ ] Create boot-volume backup/custom image or use approved restore method.
- [ ] Provision target VM in the new 10.x subnet.
- [ ] Attach/restore required data volumes.
- [ ] Reapply NSGs.
- [ ] Reapply defined tags.
- [ ] Reapply KMS settings.
- [ ] Reapply backup policy.
- [ ] Reapply monitoring agent and alarms.
- [ ] Validate hostname.
- [ ] Validate DNS.
- [ ] Validate time synchronization.
- [ ] Validate OS repositories.
- [ ] Validate CrowdStrike/security tooling.
- [ ] Validate application services.
- [ ] Validate mount points.
- [ ] Validate application dependencies.
- [ ] Validate connectivity to databases.
- [ ] Validate connectivity to on-premises through DRG/FastConnect.
- [ ] Cut DNS / application routing.
- [ ] Keep source VM stopped but recoverable during rollback window when allowed.
- [ ] Terminate old VM only under separate decommission approval.

---

# PHASE 6 — OKE / Containers / Functions / API

## 6.1 OKE

Because the migration objective includes a new VCN/CIDR, default to a **new cluster in the new landing-zone network** unless the exact OKE architecture has a verified service-supported in-place method.

- [ ] Inventory cluster.
- [ ] Inventory Kubernetes version.
- [ ] Inventory node pools.
- [ ] Inventory worker subnets.
- [ ] Inventory pod networking.
- [ ] Inventory control-plane endpoint configuration.
- [ ] Inventory NSGs.
- [ ] Inventory load balancers created by Services/Ingress.
- [ ] Inventory OCIR repositories/images.
- [ ] Inventory Kubernetes Secrets without copying secret values into evidence.
- [ ] Inventory ConfigMaps.
- [ ] Inventory PVCs and CSI volumes.
- [ ] Inventory service accounts / workload identity.
- [ ] Inventory Helm releases/manifests/GitOps sources.
- [ ] Build new OKE cluster in target 10.x subnets.
- [ ] Recreate node pools.
- [ ] Reapply IAM policies and Dynamic Groups.
- [ ] Reapply NSGs.
- [ ] Reapply add-ons.
- [ ] Reapply workloads.
- [ ] Restore/migrate persistent data.
- [ ] Validate internal/external service discovery.
- [ ] Validate ingress.
- [ ] Validate observability.
- [ ] Validate autoscaling.
- [ ] Validate application transactions.
- [ ] Shift traffic.
- [ ] Retain old cluster for rollback window.
- [ ] Decommission old cluster only after approval.

## 6.2 Container Registry

- [ ] Inventory OCIR repositories.
- [ ] Confirm target compartment access.
- [ ] Move repository where appropriate.
- [ ] Validate pull permissions from new OKE/Functions principals.
- [ ] Confirm image digests used by production workloads.

## 6.3 Functions

Functions applications support compartment moves, but networking must still be reviewed separately.

- [ ] Inventory Functions applications.
- [ ] Inventory subnet/NSG configuration.
- [ ] Inventory Vault/secret references.
- [ ] Inventory OCIR image references.
- [ ] Inventory Resource Principal policies.
- [ ] Move application only if its networking remains valid.
- [ ] Otherwise create/reconfigure application to use approved 10.x networking.
- [ ] Redeploy functions.
- [ ] Validate invocation.
- [ ] Validate database/API dependencies.
- [ ] Validate logging.

## 6.4 API Gateway / Other App Services

- [ ] Inventory gateways/deployments/routes.
- [ ] Inventory private/public endpoints.
- [ ] Inventory certificates.
- [ ] Inventory backend URLs/private IPs.
- [ ] Inventory DNS.
- [ ] Recreate/update backends to target 10.x addresses.
- [ ] Validate authentication/authorizers.
- [ ] Validate end-to-end application flows.

---

# PHASE 7 — Load Balancers

A Load Balancer can be moved to a different compartment, but that does not migrate it to a new VCN.

## 7.1 Compartment-Only Move

- [ ] Confirm destination policy.
- [ ] Move LB/NLB if network placement remains valid.
- [ ] Validate listeners.
- [ ] Validate certificates.
- [ ] Validate backend health.
- [ ] Validate WAF integration if applicable.
- [ ] Update alarms.

## 7.2 New 10.x VCN Migration

- [ ] Build replacement LB/NLB in approved target subnets.
- [ ] Match shape/flexible bandwidth.
- [ ] Recreate listeners.
- [ ] Recreate backend sets.
- [ ] Recreate health checks.
- [ ] Recreate SSL/TLS configuration.
- [ ] Recreate certificates/secrets.
- [ ] Recreate NSG attachments.
- [ ] Recreate routing policies.
- [ ] Recreate session persistence where required.
- [ ] Recreate WAF association where required.
- [ ] Register target 10.x backends.
- [ ] Validate all backends healthy.
- [ ] Validate TLS.
- [ ] Validate application health.
- [ ] Switch DNS.
- [ ] Monitor errors/latency.
- [ ] Keep old LB during rollback window.
- [ ] Remove old LB after approval.

---

# PHASE 8 — Logging, Monitoring, Security, Automation

## 8.1 Monitoring

OCI alarms can stop matching correctly after a resource moves if the metric compartment or MQL still references the old compartment.

- [ ] Inventory alarms.
- [ ] Update metric compartment.
- [ ] Remove old compartment OCIDs from MQL where required.
- [ ] Validate alarm data appears.
- [ ] Trigger approved test events.
- [ ] Confirm ONS notifications.

## 8.2 Logging / Service Connector / SIEM

- [ ] Inventory log groups.
- [ ] Inventory logs.
- [ ] Inventory Service Connector Hub connectors.
- [ ] Confirm CrowdStrike/SIEM forwarding.
- [ ] Confirm destination policies.
- [ ] Confirm new resources emit required logs.
- [ ] Confirm logging buckets/retention.
- [ ] Execute test events.
- [ ] Confirm receipt in SIEM.

## 8.3 Security Agents and Vulnerability Management

- [ ] Confirm VSS target coverage.
- [ ] Confirm host scan coverage.
- [ ] Confirm container scan coverage.
- [ ] Confirm CrowdStrike/EDR registration.
- [ ] Confirm patch/OS Management.
- [ ] Confirm Cloud Guard coverage.
- [ ] Confirm Security Zone compliance where applicable.

---

# PHASE 9 — Terraform / CD3 / Resource Manager State Reconciliation

This phase is mandatory before or immediately after resource moves. Otherwise IaC can attempt to recreate moved resources or destroy the wrong resources.

- [ ] Identify every migrated resource managed by Terraform/CD3.
- [ ] Back up Terraform state.
- [ ] Confirm the active state backend.
- [ ] Confirm no concurrent `terraform apply`.
- [ ] Freeze automated pipelines during the controlled move.
- [ ] Update compartment OCIDs in variables.
- [ ] Update VCN/subnet/NSG OCIDs.
- [ ] Update resource references.
- [ ] Import recreated resources where required.
- [ ] Use Terraform moved/import/state operations only under reviewed change control.
- [ ] Run `terraform plan`.
- [ ] Require the plan to show only intended changes.
- [ ] Resolve any proposed destruction of retained resources.
- [ ] Re-enable pipeline only after clean plan.
- [ ] Store the reviewed plan as evidence.
- [ ] Update CD3 workbook/source-of-truth to the new landing-zone state.

### Gate 9 — IaC Aligned

- [ ] No retained resource is marked for unintended destroy.
- [ ] Recreated resources are tracked by IaC where intended.
- [ ] Compartment/network OCIDs are current.
- [ ] State backup is retained.

---

# PHASE 10 — Application Cutover

## 10.1 Pre-Cutover

- [ ] Approved CRQ/change ticket.
- [ ] Application owner present/on-call.
- [ ] Infrastructure owner present/on-call.
- [ ] Database owner present/on-call if required.
- [ ] Security owner informed.
- [ ] Rollback owner assigned.
- [ ] Backups complete.
- [ ] DNS TTL reduced if needed.
- [ ] Final data synchronization complete.
- [ ] New environment health checks green.
- [ ] Monitoring dashboards open.

## 10.2 Cutover

- [ ] Stop/freeze writes where required.
- [ ] Complete final database sync.
- [ ] Switch DNS / LB / application routing.
- [ ] Switch application connection strings.
- [ ] Switch File Storage mount target where applicable.
- [ ] Validate authentication.
- [ ] Validate application login.
- [ ] Validate business transaction.
- [ ] Validate database write/read.
- [ ] Validate external integrations.
- [ ] Validate on-premises connectivity.
- [ ] Validate monitoring.
- [ ] Validate logging/SIEM.
- [ ] Validate backup.

## 10.3 Rollback Trigger

Rollback when an approved severity threshold is met, including:

- [ ] Application unavailable.
- [ ] Data validation fails.
- [ ] Database replication/cutover inconsistent.
- [ ] Critical network path fails.
- [ ] Authentication/authorization fails.
- [ ] Security control is missing.
- [ ] Monitoring/logging is blind beyond approved tolerance.
- [ ] Business owner rejects validation.

---

# PHASE 11 — Post-Migration Validation

## 11.1 Resource Validation

- [ ] Resource appears in correct target compartment.
- [ ] Resource is on approved 10.x network where required.
- [ ] Resource retains required tags.
- [ ] IAM access works.
- [ ] Dynamic Group access works.
- [ ] Vault/KMS access works.
- [ ] Backup works.
- [ ] Monitoring works.
- [ ] Logging works.
- [ ] SIEM receives events.
- [ ] Security agents healthy.
- [ ] DNS points to target.
- [ ] No production client is using old 172.16 endpoint unless explicitly approved.

## 11.2 Dependency Re-Scan

- [ ] Rerun the environment gap-analysis workflow.
- [ ] Compare pre-migration and post-migration inventories.
- [ ] Confirm migrated resources no longer depend on 172.16 where migration required.
- [ ] Confirm old-resource dependency graph has no unexpected consumers.
- [ ] Confirm new resources appear in the new landing-zone compartments.
- [ ] Resolve all new HOLD findings.

### Gate 11 — Migration Accepted

- [ ] Application owner signs off.
- [ ] Infrastructure owner signs off.
- [ ] Database owner signs off where applicable.
- [ ] Security owner signs off.
- [ ] Monitoring/logging evidence retained.
- [ ] Rollback window can begin.

---

# PHASE 12 — Old Environment Decommission Review

## 12.1 Minimum Requirements Before Destruction

No resource can be destroyed until all boxes below are checked.

- [ ] Resource is classified DECOMMISSION-CANDIDATE.
- [ ] Full dependency scan is clean.
- [ ] No DNS record points to it.
- [ ] No route table points to it.
- [ ] No NSG/security rule uniquely depends on it.
- [ ] No DRG route dependency remains.
- [ ] No load balancer backend depends on it.
- [ ] No application configuration references it.
- [ ] No database replication/backup dependency remains.
- [ ] No Terraform/CD3 state dependency remains.
- [ ] Required data is backed up/exported.
- [ ] Backup restore has been tested where required.
- [ ] Retention/legal-hold requirements are satisfied.
- [ ] Security owner approves.
- [ ] Application owner approves.
- [ ] Infrastructure owner approves.
- [ ] Change-management approval exists.
- [ ] Rollback window has expired.

## 12.2 Recommended Decommission Order

1. [ ] Disable old application entry points.
2. [ ] Remove old DNS records.
3. [ ] Remove old load balancers / API endpoints.
4. [ ] Stop old application VMs / old OKE workloads.
5. [ ] Hold powered-off/stopped resources for approved rollback period.
6. [ ] Remove old compute resources.
7. [ ] Remove obsolete block/boot volumes only after backup validation.
8. [ ] Remove obsolete database systems only after retention approval.
9. [ ] Remove obsolete File Storage mount targets/filesystems only after data validation.
10. [ ] Remove obsolete NAT/Service/Internet gateway rules.
11. [ ] Remove obsolete subnets.
12. [ ] Remove obsolete VCN route/security objects.
13. [ ] Remove old VCN only when nothing remains attached.
14. [ ] Remove obsolete DRG attachment only after route review.
15. [ ] Remove old IAM policies/Dynamic Group rules that are no longer used.
16. [ ] Delete empty old compartments only after OCI confirms all resources are removed.
17. [ ] Rerun tenancy inventory after cleanup.

---

# PHASE 13 — Evidence Package

Retain the following as the migration closeout package.

- [ ] Pre-migration inventory.
- [ ] Post-migration inventory.
- [ ] Gap-analysis output.
- [ ] Dependency graph.
- [ ] Error/coverage ledger.
- [ ] Migration register.
- [ ] Approved architecture diagram.
- [ ] Source/target compartment map.
- [ ] Source/target CIDR map.
- [ ] DRG/FastConnect routing evidence.
- [ ] IAM policy review.
- [ ] Security-rule review.
- [ ] Backup/restore evidence.
- [ ] Database validation.
- [ ] Application validation.
- [ ] Monitoring validation.
- [ ] SIEM/log validation.
- [ ] Terraform/CD3 plan after reconciliation.
- [ ] CRQ/change ticket.
- [ ] Owner approvals.
- [ ] Rollback-window completion.
- [ ] Decommission approvals.
- [ ] Final no-172.16 dependency report.

---

# Resource Migration Decision Matrix

| Resource | Compartment-only move | For migration from 172.16 to 10.x |
|---|---|---|
| VCN | Supported; preserves the VCN/network behavior | Use the new 10.x VCN; do not treat moving the old VCN as network migration |
| Subnet | Can be moved between compartments | Use target 10.x subnets |
| Route table | Can be moved between compartments | Recreate/validate rules for target VCN |
| DRG | Can be compartment-moved | Existing DRG can attach to new VCN; validate route tables/distributions/FastConnect |
| Compute instance | Supported | Rebuild/restore/launch target VM in 10.x network; cut over workload |
| Boot/block volumes | Move separately | Restore/attach to target VM as appropriate |
| Load Balancer | Supported | Build target LB/NLB in 10.x subnets and switch traffic |
| Base DB System | Supported for compatible resource types | Use DB migration/restore/replication into target 10.x DB network |
| Autonomous DB | Supported | Validate private endpoint/network design; recreate/migrate network dependency as required |
| MySQL/PostgreSQL | Service supports compartment operations for applicable resources | Provision/restore/replicate into target 10.x subnet when network must change |
| Object Storage bucket | Supported | Usually move only for governance; validate new VCN Service Gateway access/policies |
| File Storage | File system/mount-target compartment moves supported | Create target mount target/export in new subnet; switch mounts |
| OKE | Verify exact service capability | Default migration pattern: build a new cluster in target 10.x network and shift workloads |
| OCIR repository | Supported | Move for governance; validate new workload pull permissions |
| Functions application | Supported | Reconfigure/recreate networking for target subnets where required |
| API Gateway | Verify exact resource move behavior | Recreate/update endpoint/backends for target network as needed |
| Monitoring alarms | Update required when metric compartment changes | Repoint to target resources/compartments |
| Terraform/CD3 | Not an OCI resource move | Reconcile source code + state before allowing pipeline execution |

---

# Oracle Documentation References

- Managing compartments / moving resources: https://docs.oracle.com/en-us/iaas/Content/Identity/Tasks/managingcompartments.htm
- Moving a VCN: https://docs.oracle.com/en-us/iaas/Content/Network/Tasks/move_vcn_compartment.htm
- Moving a subnet: https://docs.oracle.com/en-us/iaas/Content/Network/Tasks/move_subnet_compartment.htm
- DRG management: https://docs.oracle.com/en-us/iaas/Content/Network/Tasks/manage-drg.htm
- Attaching a VCN to a DRG: https://docs.oracle.com/en-us/iaas/Content/Network/Tasks/attach-vcn-drg.htm
- Moving Compute resources: https://docs.oracle.com/en-us/iaas/Content/Compute/Tasks/movingresourcescompute.htm
- Moving an instance: https://docs.oracle.com/en-us/iaas/Content/Compute/Tasks/inst-move.htm
- Moving Block Volume resources: https://docs.oracle.com/en-us/iaas/Content/Block/Tasks/moveblockresourcecompartments.htm
- Moving a Load Balancer: https://docs.oracle.com/en-us/iaas/Content/Balance/Tasks/managingloadbalancer_topic-Moving_a_Load_Balancer_to_a_Different_Compartment.htm
- Moving an Object Storage bucket: https://docs.oracle.com/en-us/iaas/Content/Object/Tasks/managingbuckets_topic-To_move_a_bucket_to_a_different_compartment.htm
- Moving a File System: https://docs.oracle.com/en-us/iaas/Content/File/Tasks/move-file-system.htm
- Moving a File System to another subnet: https://docs.oracle.com/en-us/iaas/Content/File/Tasks/move-file-system-to-subnet.htm
- Updating an alarm after a resource move: https://docs.oracle.com/en-us/iaas/Content/Monitoring/Tasks/update-alarm-after-resource-move.htm

---

# Final Exit Criteria

The old landing zone can be declared migrated only when:

- [ ] All required workloads are operating from approved new landing-zone compartments.
- [ ] All workloads that were required to leave 172.16 are operating on approved 10.x networks.
- [ ] FastConnect/DRG/on-premises connectivity is validated.
- [ ] Production DNS resolves only to approved target endpoints.
- [ ] Databases are validated and protected.
- [ ] Applications are validated.
- [ ] OKE/Functions/API workloads are validated.
- [ ] Logging, monitoring, SIEM, vulnerability management, and security tooling are healthy.
- [ ] Terraform/CD3 state is reconciled.
- [ ] Gap analysis shows no unapproved dependency on 172.16.
- [ ] Every remaining old resource is either KEEP-SHARED, HOLD, or separately approved for decommission.
- [ ] Decommissioned resources have signed change/evidence records.
- [ ] Old compartments are empty before deletion.
