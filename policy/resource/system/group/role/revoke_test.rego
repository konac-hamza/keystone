package test_system_group_role_revoke

import data.identity.system.group.role.revoke

test_allowed if {
	revoke.allow with input as {"credentials": {"roles": ["admin"]}}
}

test_forbidden if {
	not revoke.allow with input as {"credentials": {"roles": []}}
	not revoke.allow with input as {"credentials": {"roles": ["reader"], "system": "all"}}
	not revoke.allow with input as {"credentials": {"roles": ["manager"], "system": "all"}}
	not revoke.allow with input as {"credentials": {"roles": ["member"], "system": "all"}}
}
