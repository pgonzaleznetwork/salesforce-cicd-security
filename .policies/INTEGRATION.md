# CI/CD Integration Guide

This guide explains how to integrate the OPA Salesforce Metadata Security Scanner into your existing SFDX project.

## Quick Setup

1. **Copy these files** to your SFDX project root:
   - `.github/workflows/metadata-security-scan.yml`
   - `scripts/metadata-security-scanner.js`
   - `.policies/` folder (with your security policies)
2. **Commit and push** - the workflow will run on your next PR

## What It Does

When someone opens a PR that changes permission sets:

1. 🔍 **SFDX Git Delta** identifies exactly which permission set files changed
2. 🔄 **Converts** XML metadata to JSON format  
3. 🚨 **Scans** using OPA Rego policies in `.policies/permissionsets/`
4. ❌ **Blocks PR** if security violations are found
5. ✅ **Allows merge** if all checks pass

## Example Workflow Output

```
🔍 Starting Salesforce Metadata Security Scan...

📊 Analyzing changed metadata with SFDX Git Delta...
🔍 Scanning changed permission sets for security violations...

Found 1 changed permission set(s)

🔍 Scanning ContractorAdmin.permissionset-meta.xml...
  Converted ContractorAdmin.permissionset-meta.xml to JSON
  Testing against security.rego
    ❌ VIOLATIONS FOUND:
      SECURITY VIOLATION: PermissionSet 'View All Data Violation' grants dangerous ViewAllData permission. This permission allows users to view all data in the organization regardless of sharing settings.

============================================================
📊 METADATA SECURITY SCAN RESULTS
============================================================
❌ Found 1 security violations:

📄 sgd-output/force-app/main/default/permissionsets/ContractorAdmin.permissionset-meta.xml
📋 Policy: .policies/permissionsets/security.rego
  ❌ SECURITY VIOLATION: PermissionSet 'View All Data Violation' grants dangerous ViewAllData permission. This permission allows users to view all data in the organization regardless of sharing settings.

🚫 Pull Request BLOCKED due to security violations.
Please fix the violations above before merging.
```

## Current Policies

### Permission Sets (`/.policies/permissionsets/security.rego`)
- ❌ **Blocks** ViewAllData permission assignments
- ⚠️ **Warns** about overly broad permission descriptions

## Adding New Metadata Types

To add support for other metadata types (like Custom Objects, Flows, etc.):

1. **Create policy directory**: `.policies/objects/` (for example)
2. **Add policies**: Create `.rego` files in the new directory
3. **Update scanner**: Add metadata type to `SUPPORTED_METADATA` in the workflow
4. **Test first**: Use our local testing tools to understand the JSON structure

## Local Testing

Test policies locally before committing:

```bash
# Convert XML to JSON
node scripts/xml-to-json.js path/to/permissionset.xml temp/

# Test policy
opa eval --data .policies/permissionsets/security.rego --input temp/permissionset.json "data.salesforce.permissionsets"
```

## Workflow Configuration

The workflow runs on:
- Pull requests to `main` and `develop` branches
- When files in `force-app/**` or `.policies/**` are changed

To modify trigger conditions, edit `.github/workflows/metadata-security-scan.yml`:

```yaml
on:
  pull_request:
    branches: [ main, develop ]  # Change these branches
    paths:
      - 'force-app/**'           # Salesforce metadata
      - '.policies/**'           # Policy changes
```

## Requirements

- **SFDX Project**: Must have `sfdx-project.json` in root
- **GitHub Actions**: Repository must have Actions enabled
- **Node.js 20+**: For running the scanner script

## Bypass for Emergencies

To bypass security scanning in emergency situations, add `[skip-security-scan]` to your commit message or PR title. **Use sparingly and document the reason.**
