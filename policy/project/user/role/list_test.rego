package test_project_user_role_list

import data.identity.project.user.role.list

test_allowed if {
	list.allow with input as {"credentials": {"roles": ["admin"]}}
	list.allow with input as {"credentials": {"roles": ["manager"], "domain_id": "foo", "user_id": "u1"}, "target": {"user_id": "u2", "user": {"domain_id": "foo"}, "project": {"domain_id": "foo"}, "role": {"domain_id": null}}}
	list.allow with input as {"credentials": {"roles": ["manager"], "domain_id": "foo", "user_id": "u1"}, "target": {"user_id": "u2", "user": {"domain_id": "foo"}, "project": {"domain_id": "foo"}, "role": {"domain_id": "foo"}}}
	list.allow with input as {"credentials": {"roles": ["reader"], "user_id": "u1"}, "target": {"user_id": "u1"}}
}

test_forbidden if {
	not list.allow with input as {"credentials": {"roles": []}}
	not list.allow with input as {"credentials": {"roles": ["reader"], "user_id": "u1"}, "target": {"user_id": "u2"}}
	not list.allow with input as {"credentials": {"roles": ["member"], "domain_id": "foo", "user_id": "u1"}, "target": {"user_id": "u2", "user": {"domain_id": "foo"}, "project": {"domain_id": "foo"}, "role": {"domain_id": "foo"}}}
	not list.allow with input as {"credentials": {"roles": ["manager"], "domain_id": "foo", "user_id": "u1"}, "target": {"user_id": "u2", "user": {"domain_id": "foo1"}, "project": {"domain_id": "foo1"}, "role": {"domain_id": "foo1"}}}
	not list.allow with input as {"credentials": {"roles": ["manager"], "domain_id": "foo", "user_id": "u1"}, "target": {"user_id": "u2", "user": {"domain_id": "foo"}, "project": {"domain_id": "foo"}, "role": {"domain_id": "foo1"}}}
	not list.allow with input as {"credentials": {"roles": ["reader"]}, "target": {"user_id": "u1"}}
}