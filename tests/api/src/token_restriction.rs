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
//! Token restriction (`/v4/tokens/restrictions`) REST endpoint helpers,
//! generated with [`crate::macros::crud_endpoint`].

use openstack_keystone_api_types::v4::token_restriction::*;

use crate::macros::crud_endpoint;

crud_endpoint! {
    create {
        request = TokenRestrictionCreateRequest,
        func = create_token_restriction,
        path = "tokens/restrictions",
        body_key = "restriction",
        create_type = TokenRestrictionCreate,
        model = TokenRestriction,
        response_key = "restriction",
        service = Identity,
        api_version = (4, 0),
    }
    show {
        request = TokenRestrictionShowRequest,
        func = get_token_restriction,
        path = "tokens/restrictions",
        model = TokenRestriction,
        response_key = "restriction",
        service = Identity,
        api_version = (4, 0),
    }
    // `update_put`: `crates/keystone/src/api/v4/token/restriction/update.rs`
    // declares `put`, as every v4 update handler does.
    update_put {
        request = TokenRestrictionUpdateRequest,
        func = update_token_restriction,
        path = "tokens/restrictions",
        body_key = "restriction",
        update_type = TokenRestrictionUpdate,
        model = TokenRestriction,
        response_key = "restriction",
        service = Identity,
        api_version = (4, 0),
    }
    list {
        request = TokenRestrictionListRequest,
        func = list_token_restrictions,
        path = "tokens/restrictions",
        model = TokenRestriction,
        response_key = "restrictions",
        service = Identity,
        api_version = (4, 0),
        query = [domain_id, user_id, project_id],
    }
    delete {
        request = TokenRestrictionDeleteRequest,
        func = delete_token_restriction,
        path = "tokens/restrictions",
        model = TokenRestriction,
        service = Identity,
        api_version = (4, 0),
    }
}
