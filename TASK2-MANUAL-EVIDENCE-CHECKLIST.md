# Task 2 Manual Evidence Checklist — Encryption in Transit

**Control family:** SC-8, SC-8(1), SC-13

**Purpose:** complete the evidence chain for settings that the OCI APIs do not
fully expose and validate the automated collector against the OCI Console.

Do not place completed screenshots, exported CSVs, public IPs, OCIDs, database
names, hostnames, route details or security configuration in this public
repository. Store the completed package in the approved restricted evidence
location and record only its controlled reference in the audit worksheet.

## Collection record

| Field | Value |
|---|---|
| Evidence package/reference | |
| Tenancy | |
| Region(s) | |
| Compartments | VCN / Shared Services / CD3 |
| Collector commit | |
| Collection UTC date/time | |
| Operator | |
| Reviewer | |
| Review UTC date/time | |
| Exceptions/remediation references | |

## Automated integrity gate

- [ ] `bash in-transit-encryption.sh --selfcheck` passed.
- [ ] The collector was run in every region containing in-scope resources.
- [ ] The exact VCN, Shared Services and CD3 compartment names were used.
- [ ] The process exited `0`. An exit of `3` was treated as incomplete evidence.
- [ ] Every requested compartment/service pair has a coverage row.
- [ ] No evidence row has a non-`OK` `collection_status`.
- [ ] Every hard finding and review item has an owner and disposition.
- [ ] The evidence and coverage CSV hashes were recorded in the evidence index.

## Site-to-Site VPN / IPSec

Capture each item for every in-scope IPSec connection. Redact public IPs and
OCIDs in any copy that leaves the restricted evidence location. Never capture
or export the IPSec pre-shared key.

- [ ] OCI Console connection summary showing connection name, lifecycle state,
      CPE, DRG and routing context.
- [ ] Tunnel 1 details showing `UP`, the status timestamp, IKE version, routing
      type and BGP status when BGP is used.
- [ ] Tunnel 2 details showing the same fields.
- [ ] Tunnel 1 negotiated phase-one and phase-two encryption, authentication,
      Diffie-Hellman/PFS parameters.
- [ ] Tunnel 2 negotiated phase-one and phase-two parameters.
- [ ] CPE device entry and approved device/vendor configuration reference.
- [ ] DRG attachment showing `ATTACHED`, attachment type, assigned DRG route
      table and the attached network.
- [ ] Static route list for static-routing tunnels, or BGP route/session proof
      for BGP-routing tunnels.
- [ ] Monitoring/status evidence for the review period, not only a single
      point-in-time screenshot.
- [ ] Any down tunnel, IKEv1 use, weak parameter or single-tunnel dependency has
      an approved exception or remediation ticket.

The collector intentionally uses only the read-only connection/tunnel list and
get operations documented by Oracle. It does not retrieve the shared secret.

## Load Balancers and Network Load Balancers

- [ ] Each application Load Balancer frontend listener has a certificate and an
      approved TLS protocol/cipher policy.
- [ ] Each Load Balancer backend set uses SSL/TLS, or a documented architecture
      explains why plaintext is constrained and approved.
- [ ] Peer-certificate verification posture is reviewed for every encrypted
      backend set.
- [ ] For each NLB passthrough listener, application/backend evidence proves
      where TLS terminates and which certificate/protocol policy is active.
- [ ] Certificate inventory, issuer, expiration and renewal ownership are
      recorded without exporting private keys.

## Base Database

- [ ] Sanitized `sqlnet.ora` evidence shows native network encryption required
      (`SQLNET.ENCRYPTION_SERVER=REQUIRED`) or approved TCPS configuration.
- [ ] Encryption and integrity algorithms are recorded and approved.
- [ ] Listener/service configuration proves clients use the protected endpoint.
- [ ] A connection/session check demonstrates the negotiated protection.
- [ ] Database host, listener and client evidence are matched to the Base DB row
      in the automated CSV.

## File Storage

- [ ] Each client that mounts an in-scope file system has `oci-fss-utils` or the
      approved Windows `stunnel` configuration installed.
- [ ] Linux mount/fstab evidence uses the `oci-fss` encrypted mount type, or
      Kerberos `KRB5P` is documented as the approved alternative.
- [ ] The `oci-fss-forwarder`/systemd service is active for the mounted file
      system.
- [ ] Network rules permit the approved encrypted File Storage path (TCP 2051)
      and do not rely on plaintext NFS for the protected workload.
- [ ] Client mount evidence is matched to each FSS mount-target row.

Oracle reference: [Using In-transit TLS Encryption](https://docs.oracle.com/en-us/iaas/Content/File/Tasks/intransitencryption.htm).

## Databases, Object Storage, API Gateway and OKE

- [ ] Autonomous Database connection profiles and mTLS policy match the CSV.
- [ ] Object Storage clients use HTTPS endpoints; public-access findings are
      reviewed separately from transport encryption.
- [ ] API Gateway custom domains/certificates and backend TLS are included where
      platform endpoint evidence alone is insufficient.
- [ ] OKE API endpoint exposure is reviewed and workload ingress/service-mesh
      encryption is evidenced separately from Kubernetes API TLS.

## Review and approval

- [ ] Reviewer reconciled screenshot/config evidence to every automated review
      row (`MANUAL-EVIDENCE-*` and `*-REVIEW-*`).
- [ ] Findings have corrective-action owners, due dates and ticket references.
- [ ] Accepted risks include scope, rationale, approver and expiration date.
- [ ] Evidence package is access-controlled, immutable per the evidence policy
      and referenced from the Continuous Monitoring/audit worksheet.
- [ ] Reviewer signed and dated the completed checklist.

