# METADATA
# description: Policy for creating application credentials
package identity.user.application_credential.create

default allow := false

allow if {
    input.credentials.user_id == input.target.user_id
}