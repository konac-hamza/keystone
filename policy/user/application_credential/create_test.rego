package test_application_credential_create

import data.identity.user.application_credential.create

test_owner_allowed if {
    create.allow with input as {"credentials": {"user_id": "uid"}, "target": {"user_id": "uid"}}
}

test_non_owner_forbidden if {
    not create.allow with input as {"credentials": {"user_id": "other"}, "target": {"user_id": "uid"}}
}