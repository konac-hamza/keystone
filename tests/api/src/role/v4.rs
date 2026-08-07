// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0
//! v4 role CRUD helpers, generated with [`crate::macros::crud_endpoint`].
//!
//! `crates/keystone/src/api/v4/role/mod.rs` returns the **v3** router, so
//! `/v4/roles` is served by the v3 handlers and keeps their `PATCH` update
//! verb (unlike the natively-v4 handlers, which use `PUT`). Only the
//! `/v4` path prefix differs from [`crate::role`].

use openstack_keystone_api_types::v3::role::*;

use crate::macros::crud_endpoint;

crud_endpoint! {
    create {
        request = RoleV4CreateApiRequest,
        func = create_role_v4,
        path = "roles",
        body_key = "role",
        create_type = RoleCreate,
        model = Role,
        response_key = "role",
        service = Identity,
        api_version = (4, 0),
    }
    show {
        request = RoleV4ShowApiRequest,
        func = get_role_v4,
        path = "roles",
        model = Role,
        response_key = "role",
        service = Identity,
        api_version = (4, 0),
    }
    // `update`, not `update_put`: `/v4/roles` re-mounts the v3 handler,
    // whose `#[utoipa::path]` declares `patch`.
    update {
        request = RoleV4UpdateApiRequest,
        func = update_role_v4,
        path = "roles",
        body_key = "role",
        update_type = RoleUpdate,
        model = Role,
        response_key = "role",
        service = Identity,
        api_version = (4, 0),
    }
    list {
        request = RoleV4ListRequest,
        func = list_roles_v4,
        path = "roles",
        model = Role,
        response_key = "roles",
        service = Identity,
        api_version = (4, 0),
        query = [domain_id, name],
    }
    // `delete_fn`, not `delete`: `v3::role::Role` already carries the
    // `DeletableResource` impl from `crate::role`.
    delete_fn {
        request = RoleV4DeleteApiRequest,
        func = delete_role_v4,
        path = "roles",
        service = Identity,
        api_version = (4, 0),
    }
}
