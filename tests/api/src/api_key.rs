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
//! API Key (SCIM ingress machine identity, ADR 0021) REST endpoint helpers.
//!
//! `test_api::scim` uses `create`/`revoke` to obtain a live bearer token for
//! SCIM ingress requests; the remaining wrappers exercise the admin CRUD
//! surface itself from `tests/api_v4/api_key.rs`.
//!
//! Every operation carries `domain_id`: `show`, `update` and `revoke` take it
//! as a query parameter, `list` as part of `ApiKeyListParameters` (where it is
//! mandatory, ADR 0021 §5.B), and `simulate_access` in its JSON body. That
//! mix is why these stay hand-written rather than using
//! [`crate::macros::crud_endpoint`].

use std::borrow::Cow;
use std::sync::Arc;

use chrono::{Duration, Utc};
use eyre::Result;

use openstack_keystone_api_types::v4::api_key::{
    ApiKey, ApiKeyCreate, ApiKeyCreateResponse, ApiKeySimulateAccessResponse, ApiKeyUpdate,
};
use openstack_sdk::api::rest_endpoint_prelude::*;
use openstack_sdk::{AsyncOpenStack, api::QueryAsync};

use crate::guard::*;

#[derive(Clone, Debug)]
struct ApiKeyCreateApiRequest {
    api_key: ApiKeyCreate,
}

impl RestEndpoint for ApiKeyCreateApiRequest {
    fn method(&self) -> http::Method {
        http::Method::POST
    }

    fn endpoint(&self) -> Cow<'static, str> {
        "api-keys".into()
    }

    fn body(&self) -> Result<Option<(&'static str, Vec<u8>)>, BodyError> {
        let mut params = JsonBodyParams::default();
        params.push("api_key", serde_json::to_value(&self.api_key)?);
        params.into_body()
    }

    fn service_type(&self) -> ServiceType {
        ServiceType::Identity
    }

    fn api_version(&self) -> Option<ApiVersion> {
        Some(ApiVersion::new(4, 0))
    }
}

/// Create a new API Key, returning the metadata plus the one-time bearer
/// token (`kscim_...`).
pub async fn create_api_key(
    tc: &Arc<AsyncOpenStack>,
    api_key: ApiKeyCreate,
) -> Result<AsyncResourceGuard<ApiKeyCreateResponse>> {
    let obj: ApiKeyCreateResponse = ApiKeyCreateApiRequest { api_key }
        .query_async(tc.as_ref())
        .await?;
    Ok(AsyncResourceGuard::new(obj, tc.clone()))
}

/// A key valid for an hour, bound to `provider_id` in `domain_id`.
pub fn sample_api_key_create(domain_id: &str, provider_id: &str) -> ApiKeyCreate {
    ApiKeyCreate {
        allowed_ips: None,
        description: Some("test_api scim provisioning key".to_string()),
        domain_id: domain_id.to_string(),
        expires_at: Utc::now() + Duration::hours(1),
        provider_id: provider_id.to_string(),
    }
}

struct ApiKeyRevokeRequest<'a> {
    client_id: Cow<'a, str>,
    domain_id: Cow<'a, str>,
}

impl RestEndpoint for ApiKeyRevokeRequest<'_> {
    fn method(&self) -> http::Method {
        http::Method::POST
    }

    fn endpoint(&self) -> Cow<'static, str> {
        format!("api-keys/{}/revoke", self.client_id).into()
    }

    fn parameters(&self) -> QueryParams<'_> {
        let mut params = QueryParams::default();
        params.push("domain_id", self.domain_id.as_ref());
        params
    }

    fn service_type(&self) -> ServiceType {
        ServiceType::Identity
    }

    /// Revoke answers with the revoked key under `api_key`. The
    /// [`DeletableResource`] path discards the body, so this only matters to
    /// [`revoke_api_key`].
    fn response_key(&self) -> Option<Cow<'static, str>> {
        Some("api_key".into())
    }

    fn api_version(&self) -> Option<ApiVersion> {
        Some(ApiVersion::new(4, 0))
    }
}

#[async_trait::async_trait]
impl DeletableResource for ApiKeyCreateResponse {
    async fn delete(&self, state: &Arc<AsyncOpenStack>) -> Result<()> {
        Ok(openstack_sdk::api::ignore(ApiKeyRevokeRequest {
            client_id: self.api_key.client_id.clone().into(),
            domain_id: self.api_key.domain_id.clone().into(),
        })
        .query_async(state.as_ref())
        .await?)
    }
}

/// `GET /v4/api-keys/{client_id}?domain_id=…`.
///
/// `response_key` is left unset so the same request can serve both the
/// typed and the raw-JSON accessor; the typed one extracts `api_key`
/// itself.
#[derive(Clone, Debug)]
struct ApiKeyShowRequest<'a> {
    client_id: Cow<'a, str>,
    domain_id: Cow<'a, str>,
}

impl RestEndpoint for ApiKeyShowRequest<'_> {
    fn method(&self) -> http::Method {
        http::Method::GET
    }

    fn endpoint(&self) -> Cow<'static, str> {
        format!("api-keys/{}", self.client_id).into()
    }

    fn parameters(&self) -> QueryParams<'_> {
        let mut params = QueryParams::default();
        params.push("domain_id", self.domain_id.as_ref());
        params
    }

    fn service_type(&self) -> ServiceType {
        ServiceType::Identity
    }

    fn api_version(&self) -> Option<ApiVersion> {
        Some(ApiVersion::new(4, 0))
    }
}

/// The whole `GET /v4/api-keys/{client_id}` body, undecoded.
///
/// Deserialising into [`ApiKey`] cannot prove a secret was withheld —
/// `ApiKey` has no `deny_unknown_fields`, so `token`/`secret_hash`/
/// `lookup_hash` would be dropped silently. Assertions about absent fields
/// must read this.
pub async fn get_api_key_raw(
    tc: &Arc<AsyncOpenStack>,
    domain_id: &str,
    client_id: &str,
) -> Result<serde_json::Value> {
    Ok(ApiKeyShowRequest {
        client_id: client_id.into(),
        domain_id: domain_id.into(),
    }
    .query_async(tc.as_ref())
    .await?)
}

/// Fetch a single API Key's metadata.
pub async fn get_api_key(
    tc: &Arc<AsyncOpenStack>,
    domain_id: &str,
    client_id: &str,
) -> Result<ApiKey> {
    let body = get_api_key_raw(tc, domain_id, client_id).await?;
    Ok(serde_json::from_value(
        body.get("api_key")
            .cloned()
            .ok_or_else(|| eyre::eyre!("`api_key` missing from show response: {body}"))?,
    )?)
}

/// `GET /v4/api-keys?domain_id=…`. `domain_id` is a mandatory filter.
#[derive(Clone, Debug)]
struct ApiKeyListRequest<'a> {
    domain_id: Cow<'a, str>,
    provider_id: Option<Cow<'a, str>>,
}

impl RestEndpoint for ApiKeyListRequest<'_> {
    fn method(&self) -> http::Method {
        http::Method::GET
    }

    fn endpoint(&self) -> Cow<'static, str> {
        "api-keys".into()
    }

    fn parameters(&self) -> QueryParams<'_> {
        let mut params = QueryParams::default();
        params.push("domain_id", self.domain_id.as_ref());
        if let Some(provider_id) = &self.provider_id {
            params.push("provider_id", provider_id.as_ref());
        }
        params
    }

    fn service_type(&self) -> ServiceType {
        ServiceType::Identity
    }

    fn api_version(&self) -> Option<ApiVersion> {
        Some(ApiVersion::new(4, 0))
    }
}

/// The whole `GET /v4/api-keys` body, undecoded — see [`get_api_key_raw`].
pub async fn list_api_keys_raw(
    tc: &Arc<AsyncOpenStack>,
    domain_id: &str,
    provider_id: Option<&str>,
) -> Result<serde_json::Value> {
    Ok(ApiKeyListRequest {
        domain_id: domain_id.into(),
        provider_id: provider_id.map(Into::into),
    }
    .query_async(tc.as_ref())
    .await?)
}

/// List a domain's API Keys, optionally narrowed to one `provider_id`.
pub async fn list_api_keys(
    tc: &Arc<AsyncOpenStack>,
    domain_id: &str,
    provider_id: Option<&str>,
) -> Result<Vec<ApiKey>> {
    let body = list_api_keys_raw(tc, domain_id, provider_id).await?;
    Ok(serde_json::from_value(
        body.get("api_keys")
            .cloned()
            .ok_or_else(|| eyre::eyre!("`api_keys` missing from list response: {body}"))?,
    )?)
}

/// `PUT /v4/api-keys/{client_id}?domain_id=…` — v4 updates use `PUT`.
#[derive(Clone, Debug)]
struct ApiKeyUpdateRequest<'a> {
    client_id: Cow<'a, str>,
    domain_id: Cow<'a, str>,
    api_key: ApiKeyUpdate,
}

impl RestEndpoint for ApiKeyUpdateRequest<'_> {
    fn method(&self) -> http::Method {
        http::Method::PUT
    }

    fn endpoint(&self) -> Cow<'static, str> {
        format!("api-keys/{}", self.client_id).into()
    }

    fn parameters(&self) -> QueryParams<'_> {
        let mut params = QueryParams::default();
        params.push("domain_id", self.domain_id.as_ref());
        params
    }

    fn body(&self) -> Result<Option<(&'static str, Vec<u8>)>, BodyError> {
        let mut params = JsonBodyParams::default();
        params.push("api_key", serde_json::to_value(&self.api_key)?);
        params.into_body()
    }

    fn service_type(&self) -> ServiceType {
        ServiceType::Identity
    }

    fn response_key(&self) -> Option<Cow<'static, str>> {
        Some("api_key".into())
    }

    fn api_version(&self) -> Option<ApiVersion> {
        Some(ApiVersion::new(4, 0))
    }
}

/// Update an API Key's mutable metadata.
pub async fn update_api_key(
    tc: &Arc<AsyncOpenStack>,
    domain_id: &str,
    client_id: &str,
    api_key: ApiKeyUpdate,
) -> Result<ApiKey> {
    Ok(ApiKeyUpdateRequest {
        client_id: client_id.into(),
        domain_id: domain_id.into(),
        api_key,
    }
    .query_async(tc.as_ref())
    .await?)
}

/// `POST /v4/api-keys/{client_id}/revoke?domain_id=…`, returning the
/// revoked key. [`DeletableResource`] drives the same endpoint for guard
/// cleanup but discards the response.
pub async fn revoke_api_key(
    tc: &Arc<AsyncOpenStack>,
    domain_id: &str,
    client_id: &str,
) -> Result<ApiKey> {
    Ok(ApiKeyRevokeRequest {
        client_id: client_id.into(),
        domain_id: domain_id.into(),
    }
    .query_async(tc.as_ref())
    .await?)
}

/// `POST /v4/api-keys/simulate-access`.
///
/// Unlike the other operations this takes `client_id` and `domain_id` in a
/// **JSON body**, not as query parameters.
#[derive(Clone, Debug)]
struct ApiKeySimulateAccessApiRequest<'a> {
    client_id: Cow<'a, str>,
    domain_id: Cow<'a, str>,
}

impl RestEndpoint for ApiKeySimulateAccessApiRequest<'_> {
    fn method(&self) -> http::Method {
        http::Method::POST
    }

    fn endpoint(&self) -> Cow<'static, str> {
        "api-keys/simulate-access".into()
    }

    fn body(&self) -> Result<Option<(&'static str, Vec<u8>)>, BodyError> {
        let mut params = JsonBodyParams::default();
        params.push("client_id", serde_json::to_value(self.client_id.as_ref())?);
        params.push("domain_id", serde_json::to_value(self.domain_id.as_ref())?);
        params.into_body()
    }

    fn service_type(&self) -> ServiceType {
        ServiceType::Identity
    }

    fn api_version(&self) -> Option<ApiVersion> {
        Some(ApiVersion::new(4, 0))
    }
}

/// Resolve an API Key's authorization topology without presenting its token.
pub async fn simulate_api_key_access(
    tc: &Arc<AsyncOpenStack>,
    domain_id: &str,
    client_id: &str,
) -> Result<ApiKeySimulateAccessResponse> {
    Ok(ApiKeySimulateAccessApiRequest {
        client_id: client_id.into(),
        domain_id: domain_id.into(),
    }
    .query_async(tc.as_ref())
    .await?)
}
