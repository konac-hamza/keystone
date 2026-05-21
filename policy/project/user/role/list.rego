# METADATA
# description: Policy for listing roles of a user in a project
package identity.project.user.role.list

import data.identity
import data.identity.assignment

default allow := false

allow if {
    "admin" in input.credentials.roles
}

allow if {
    "manager" in input.credentials.roles
    assignment.project_role_domain_matches
}

allow if {
    input.credentials.user_id == input.target.user_id
}

violation contains {"field": "user_id", "msg": "listing roles requires admin, a domain-scoped manager, or the requesting user to match the target user."} if {
    not "admin" in input.credentials.roles
    not "manager" in input.credentials.roles
    input.credentials.user_id != input.target.user_id
}