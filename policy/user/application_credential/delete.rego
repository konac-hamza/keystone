# METADATA
# description: Policy for deleting application credentials
package identity.user.application_credential.delete

default allow := false

allow if { input.credentials.is_admin }

allow if { input.credentials.user_id == input.target.user_id }