package test_application_credential_delete

import data.identity.user.application_credential.delete

test_admin_allowed if {
    delete.allow with input as {"credentials": {"is_admin": true}, "target": {"user_id": "uid"}}
}

test_owner_allowed if {
    delete.allow with input as {"credentials": {"user_id": "uid"}, "target": {"user_id": "uid"}}
}

test_non_owner_forbidden if {
    not delete.allow with input as {"credentials": {"user_id": "other", "roles": []}, "target": {"user_id": "uid"}}
}