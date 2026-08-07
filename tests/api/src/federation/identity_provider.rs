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
//! Federation identity provider REST endpoint helpers, generated with
//! [`crate::macros::crud_endpoint`].
//!
//! The routes live under `/v4` only — `crates/keystone/src/api/v4/mod.rs`
//! nests `federation` and `api::v3` does not — so despite issue #993 listing
//! them among the v3 holes, the suite is `tests/api_v4/federation/`.
//!
//! `test_api::scim_realm` and `test_api::scim` only need create and delete,
//! to provision a realm's required `idp_id`; the remaining wrappers exercise
//! the full CRUD surface from `tests/api_v4/federation/identity_provider.rs`.

use std::borrow::Cow;
use std::sync::Arc;

use eyre::Result;

use openstack_keystone_api_types::federation::{
    IdentityProvider, IdentityProviderCreate, IdentityProviderCreateBuilder, IdentityProviderUpdate,
};
use openstack_sdk::api::rest_endpoint_prelude::*;
use openstack_sdk::{AsyncOpenStack, api::QueryAsync};

use crate::macros::crud_endpoint;

crud_endpoint! {
    create {
        request = IdentityProviderCreateApiRequest,
        func = create_identity_provider,
        path = "federation/identity_providers",
        body_key = "identity_provider",
        create_type = IdentityProviderCreate,
        model = IdentityProvider,
        response_key = "identity_provider",
        service = Identity,
        api_version = (4, 0),
    }
    show {
        request = IdentityProviderShowRequest,
        func = get_identity_provider,
        path = "federation/identity_providers",
        model = IdentityProvider,
        response_key = "identity_provider",
        service = Identity,
        api_version = (4, 0),
    }
    // `update_put`: the v4 update handler declares `put`.
    update_put {
        request = IdentityProviderUpdateApiRequest,
        func = update_identity_provider,
        path = "federation/identity_providers",
        body_key = "identity_provider",
        update_type = IdentityProviderUpdate,
        model = IdentityProvider,
        response_key = "identity_provider",
        service = Identity,
        api_version = (4, 0),
    }
    list {
        request = IdentityProviderListRequest,
        func = list_identity_providers,
        path = "federation/identity_providers",
        model = IdentityProvider,
        response_key = "identity_providers",
        service = Identity,
        api_version = (4, 0),
        query = [name, domain_id],
    }
    delete {
        request = IdentityProviderDeleteRequest,
        func = delete_identity_provider,
        path = "federation/identity_providers",
        model = IdentityProvider,
        service = Identity,
        api_version = (4, 0),
    }
}

/// A realm-ready identity provider create payload: SCIM realm creation only
/// validates that `idp_id` resolves, so the OIDC/JWT plumbing fields are
/// left unset.
pub fn sample_identity_provider_create(domain_id: &str, name: &str) -> IdentityProviderCreate {
    IdentityProviderCreateBuilder::default()
        .name(name)
        .domain_id(domain_id)
        .build()
        .expect("valid identity provider create payload")
}

/// `GET /v4/federation/identity_providers/{idp_id}` with `response_key`
/// deliberately unset. The macro-generated `show` always unwraps
/// `identity_provider`, so reading the envelope needs its own request.
#[derive(Clone, Debug)]
struct IdentityProviderShowRawRequest<'a> {
    idp_id: Cow<'a, str>,
}

impl RestEndpoint for IdentityProviderShowRawRequest<'_> {
    fn method(&self) -> http::Method {
        http::Method::GET
    }

    fn endpoint(&self) -> Cow<'static, str> {
        format!("federation/identity_providers/{}", self.idp_id).into()
    }

    fn service_type(&self) -> ServiceType {
        ServiceType::Identity
    }

    fn api_version(&self) -> Option<ApiVersion> {
        Some(ApiVersion::new(4, 0))
    }
}

/// The whole show body, undecoded.
///
/// [`IdentityProvider`] deliberately has no `oidc_client_secret` field, so a
/// typed decode would silently drop one that leaked. Assertions about the
/// secret being withheld must read this.
pub async fn get_identity_provider_raw(
    tc: &Arc<AsyncOpenStack>,
    idp_id: &str,
) -> Result<serde_json::Value> {
    Ok(IdentityProviderShowRawRequest {
        idp_id: idp_id.into(),
    }
    .query_async(tc.as_ref())
    .await?)
}
