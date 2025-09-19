package salesforce.permissionsets

# Deny if a PermissionSet grants ViewAllData permission
deny[msg] if {
  # Check if PermissionSet exists in input
  input.PermissionSet
  
  # Check if userPermissions exists and contains ViewAllData
  input.PermissionSet.userPermissions.name == "ViewAllData"
  input.PermissionSet.userPermissions.enabled == "true"
  
  # Get the permission set label for the error message
  label := input.PermissionSet.label
  
  msg := sprintf("SECURITY VIOLATION: PermissionSet '%s' grants dangerous ViewAllData permission. This permission allows users to view all data in the organization regardless of sharing settings.", [label])
}

# Additional check for arrays of userPermissions (in case there are multiple)
deny[msg] if {
  input.PermissionSet
  
  # Handle case where userPermissions is an array
  some i
  input.PermissionSet.userPermissions[i].name == "ViewAllData"
  input.PermissionSet.userPermissions[i].enabled == "true"
  
  label := input.PermissionSet.label
  
  msg := sprintf("SECURITY VIOLATION: PermissionSet '%s' grants dangerous ViewAllData permission. This permission allows users to view all data in the organization regardless of sharing settings.", [label])
}

# Warning for permission sets with overly broad descriptions mentioning "all data"
warn[msg] if {
  input.PermissionSet
  description := input.PermissionSet.description
  
  # Check if description contains concerning phrases
  contains(lower(description), "all data")
  contains(lower(description), "comprehensive access")
  
  label := input.PermissionSet.label
  
  msg := sprintf("WARNING: PermissionSet '%s' has a description suggesting broad data access. Please review permissions to ensure principle of least privilege.", [label])
}
