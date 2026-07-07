# METADATA
# description: Policy for showing application credential details
package identity.user.application_credential.show

default allow := false

allow if { input.credentials.is_admin }

allow if {
    "reader" in input.credentials.roles
    input.credentials.system == "all"
}

allow if { input.credentials.user_id == input.target.user_id }