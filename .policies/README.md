# Salesforce Metadata Security Policies

This directory contains OPA (Open Policy Agent) Rego policies for scanning Salesforce metadata for security vulnerabilities and compliance violations.

## Structure

Each subdirectory corresponds to a Salesforce metadata type and contains Rego policies that will be executed against changed metadata of that type during CI/CD.

```
.policies/
└── permissionsets/     # PermissionSet metadata policies
```

**Note**: Currently only PermissionSet policies are implemented. Additional metadata types can be added as subdirectories when needed.

## Policy Writing Guidelines

### Package Naming Convention
Each policy file should use the package naming convention:
```rego
package salesforce.{metadata_type}
```

For example:
- `package salesforce.permissionsets`
- `package salesforce.objects`
- `package salesforce.flows`

### Policy Structure
Use `deny[msg]` for security violations and `warn[msg]` for warnings:

```rego
package salesforce.permissionsets

# Deny dangerous permissions
deny[msg] if {
  input.PermissionSet.userPermissions.name == "ViewAllData"
  input.PermissionSet.userPermissions.enabled == "true"
  msg := sprintf("SECURITY VIOLATION: PermissionSet '%s' grants dangerous ViewAllData permission", [input.PermissionSet.label])
}

# Warn about broad access descriptions  
warn[msg] if {
  contains(lower(input.PermissionSet.description), "all data")
  msg := sprintf("WARNING: PermissionSet '%s' description suggests broad access", [input.PermissionSet.label])
}
```

### Input Data Format
The input to policies will be JSON representations of the Salesforce metadata XML files, converted using xml2js with the following settings:
- `explicitArray: false`
- `ignoreAttrs: false` 
- `attrkey: '@'`
- `charkey: '#text'`

### Testing Policies Locally
You can test policies locally using:

```bash
# Convert XML to JSON
node scripts/xml-to-json.js path/to/metadata.xml temp/

# Test policy  
opa eval --data .policies/permissionsets/security.rego --input temp/metadata.json "data.salesforce.permissionsets"
```

## Metadata Type Mapping

| Salesforce Metadata Type | Policy Directory | File Extensions |
|---------------------------|------------------|-----------------|
| PermissionSet | `permissionsets/` | `.permissionset-meta.xml` |

*Additional metadata types will be added as needed*

## CI/CD Integration

The GitHub Actions workflow will:

1. Use SFDX Git Delta to identify changed metadata files
2. Convert XML metadata to JSON format
3. Map each changed file to its corresponding policy directory
4. Execute all Rego policies in that directory against the metadata
5. Aggregate results and fail the PR if any violations are found

## Example Policies

See the example policies in each subdirectory for common security patterns:

- **Permission Sets**: Detect dangerous permissions like ViewAllData, ModifyAllData
