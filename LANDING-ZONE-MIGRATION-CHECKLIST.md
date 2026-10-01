# OCI Old-to-New Landing Zone Migration Checklist

**Last updated:** 2026-10-01

**Goal:** Move legacy OCI resources from old compartments and the old `172.16.x.x` environment into the new landing-zone compartments and approved `10.x` network.

## Checklist

1. **Inventory old resources**
   - VCNs/subnets
   - VMs
   - Databases
   - Load balancers
   - OKE
   - Storage
   - DNS
   - IAM/policies
   - Monitoring/logging

2. **Identify old dependencies**
   - `172.16.x.x`
   - Old compartments
   - DRG/FastConnect
   - DNS
   - App/database connections
   - Terraform/CD3 state

3. **Prepare new landing zone**
   - Target compartments
   - `10.x` VCN/subnets
   - NSGs/routes
   - IAM policies
   - KMS/Vault
   - Logging/monitoring

4. **Connect new network**
   - Attach new VCN to DRG
   - Validate FastConnect
   - Update routes
   - Test on-prem → OCI
   - Test OCI → on-prem

5. **Move shared services/storage**
   - Object Storage
   - Block volumes
   - File Storage
   - Backups

6. **Migrate databases**
   - Build/restore DB in new `10.x` subnet
   - Sync data
   - Test connectivity
   - Update connection strings

7. **Migrate VMs/apps**
   - Backup/image old VM
   - Launch VM in `10.x`
   - Attach storage
   - Apply NSGs
   - Test app

8. **Migrate OKE / LB / API**
   - New OKE cluster if needed
   - New LB/NLB
   - Update API backends
   - Test traffic

9. **Update DNS**
   - Point DNS to new resources
   - Validate application access

10. **Update monitoring/security**
   - Alarms
   - Logging
   - SIEM/CrowdStrike
   - Vulnerability scanning

11. **Update Terraform/CD3**
   - Update compartment OCIDs
   - Update subnet/VCN OCIDs
   - Reconcile state
   - Run clean `terraform plan`

12. **Validate**
   - Apps working
   - DB working
   - Backups working
   - FastConnect working
   - Monitoring/logging working

13. **Rerun gap analysis**
   - Confirm no required resources still depend on `172.16.x.x`

14. **Decommission old environment**
   - Stop old workloads
   - Wait through rollback period
   - Remove old VMs/DB/LBs
   - Remove old subnets/VCN
   - Remove obsolete IAM policies
   - Delete old compartments last

> **Rule:** **Move compartment ≠ migrate network.** Anything still using `172.16.x.x` is not fully migrated until it is operating on the new `10.x` network.
