# METADATA
# description: Policy for revoking roles from groups on system
package identity.system.group.role.revoke

default allow := false

allow if {
	"admin" in input.credentials.roles
}

allow if {
	input.credentials.is_admin
}

violation contains {"field": "system", "msg": "revoking a role from a group on the system requires admin role."} if {
	not "admin" in input.credentials.roles
}
