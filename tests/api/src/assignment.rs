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

use std::{borrow::Cow, sync::Arc};

use derive_builder::Builder;
use eyre::Result;

use openstack_sdk::api::rest_endpoint_prelude::*;
use openstack_sdk::{AsyncOpenStack, api::QueryAsync};

/// Grant roles to users on project and system scopes.
pub mod grant {
    use super::*;

    #[derive(Builder, Clone, Debug)]
    #[builder(setter(strip_option, into))]
    struct ProjectUserRoleGrant<'a> {
        project_id: Cow<'a, str>,
        user_id: Cow<'a, str>,
        role_id: Cow<'a, str>,
    }

    impl RestEndpoint for ProjectUserRoleGrant<'_> {
        fn method(&self) -> http::Method {
            http::Method::PUT
        }

        fn endpoint(&self) -> Cow<'static, str> {
            format!(
                "projects/{}/users/{}/roles/{}",
                self.project_id, self.user_id, self.role_id
            )
            .into()
        }

        fn service_type(&self) -> ServiceType {
            ServiceType::Identity
        }

        fn api_version(&self) -> Option<ApiVersion> {
            Some(ApiVersion::new(3, 0))
        }
    }

    #[derive(Builder, Clone, Debug)]
    #[builder(setter(strip_option, into))]
    struct SystemUserRoleGrant<'a> {
        user_id: Cow<'a, str>,
        role_id: Cow<'a, str>,
    }

    impl RestEndpoint for SystemUserRoleGrant<'_> {
        fn method(&self) -> http::Method {
            http::Method::PUT
        }

        fn endpoint(&self) -> Cow<'static, str> {
            format!("system/users/{}/roles/{}", self.user_id, self.role_id).into()
        }

        fn service_type(&self) -> ServiceType {
            ServiceType::Identity
        }

        fn api_version(&self) -> Option<ApiVersion> {
            Some(ApiVersion::new(3, 0))
        }
    }

    /// Grant `role_id` to `user_id` on `project_id`. The grant is a PUT and is
    /// cleaned up implicitly when the project or user is deleted.
    pub async fn add_project_grant<P, U, R>(
        client: &Arc<AsyncOpenStack>,
        project_id: P,
        user_id: U,
        role_id: R,
    ) -> Result<()>
    where
        P: AsRef<str>,
        U: AsRef<str>,
        R: AsRef<str>,
    {
        openstack_sdk::api::ignore(
            ProjectUserRoleGrantBuilder::default()
                .project_id(project_id.as_ref())
                .user_id(user_id.as_ref())
                .role_id(role_id.as_ref())
                .build()?,
        )
        .query_async(client.as_ref())
        .await?;
        Ok(())
    }

    /// Grant `role_id` to `user_id` on the system scope. The grant is cleaned
    /// up implicitly when the user is deleted.
    pub async fn add_system_grant<U, R>(
        client: &Arc<AsyncOpenStack>,
        user_id: U,
        role_id: R,
    ) -> Result<()>
    where
        U: AsRef<str>,
        R: AsRef<str>,
    {
        openstack_sdk::api::ignore(
            SystemUserRoleGrantBuilder::default()
                .user_id(user_id.as_ref())
                .role_id(role_id.as_ref())
                .build()?,
        )
        .query_async(client.as_ref())
        .await?;
        Ok(())
    }
}

/// The same grant/check/list/revoke surface through `/v4`.
///
/// `crates/keystone/src/api/v4/role_assignment/mod.rs` re-mounts the v3
/// router, and the sub-routes carry absolute paths, so v4 publishes
/// `/v4/projects/…`, `/v4/system/…` and `/v4/role_assignments` — the same
/// shapes as v3, one version prefix up.
pub mod v4 {
    use super::*;

    // The grant-listing endpoints answer with
    // `RoleAssignmentRoleList { roles: Vec<role_assignment::Role> }`, whose
    // `Role` carries an *optional* `name` — not `v3::role::Role`, which
    // requires it.
    use openstack_keystone_api_types::v3::role_assignment::{Assignment, Role};

    /// Endpoint targeting a single `{scope}/users/{user}/roles/{role}`
    /// triple, parameterised by HTTP method so grant (PUT), check (HEAD)
    /// and revoke (DELETE) share one impl.
    #[derive(Clone, Debug)]
    struct RoleAssignmentV4Request {
        method: http::Method,
        endpoint: String,
    }

    impl RestEndpoint for RoleAssignmentV4Request {
        fn method(&self) -> http::Method {
            self.method.clone()
        }

        fn endpoint(&self) -> Cow<'static, str> {
            self.endpoint.clone().into()
        }

        fn service_type(&self) -> ServiceType {
            ServiceType::Identity
        }

        fn api_version(&self) -> Option<ApiVersion> {
            Some(ApiVersion::new(4, 0))
        }
    }

    async fn ignore_v4(
        client: &Arc<AsyncOpenStack>,
        method: http::Method,
        endpoint: String,
    ) -> Result<()> {
        openstack_sdk::api::ignore(RoleAssignmentV4Request { method, endpoint })
            .query_async(client.as_ref())
            .await?;
        Ok(())
    }

    fn project_role_path(project_id: &str, user_id: &str, role_id: &str) -> String {
        format!("projects/{project_id}/users/{user_id}/roles/{role_id}")
    }

    fn system_role_path(user_id: &str, role_id: &str) -> String {
        format!("system/users/{user_id}/roles/{role_id}")
    }

    /// `PUT /v4/projects/{project_id}/users/{user_id}/roles/{role_id}`.
    pub async fn grant_project_role_v4(
        client: &Arc<AsyncOpenStack>,
        project_id: &str,
        user_id: &str,
        role_id: &str,
    ) -> Result<()> {
        ignore_v4(
            client,
            http::Method::PUT,
            project_role_path(project_id, user_id, role_id),
        )
        .await
    }

    /// `HEAD /v4/projects/{project_id}/users/{user_id}/roles/{role_id}`.
    pub async fn check_project_role_v4(
        client: &Arc<AsyncOpenStack>,
        project_id: &str,
        user_id: &str,
        role_id: &str,
    ) -> Result<()> {
        ignore_v4(
            client,
            http::Method::HEAD,
            project_role_path(project_id, user_id, role_id),
        )
        .await
    }

    /// `DELETE /v4/projects/{project_id}/users/{user_id}/roles/{role_id}`.
    pub async fn revoke_project_role_v4(
        client: &Arc<AsyncOpenStack>,
        project_id: &str,
        user_id: &str,
        role_id: &str,
    ) -> Result<()> {
        ignore_v4(
            client,
            http::Method::DELETE,
            project_role_path(project_id, user_id, role_id),
        )
        .await
    }

    /// `PUT /v4/system/users/{user_id}/roles/{role_id}`.
    pub async fn grant_system_role_v4(
        client: &Arc<AsyncOpenStack>,
        user_id: &str,
        role_id: &str,
    ) -> Result<()> {
        ignore_v4(
            client,
            http::Method::PUT,
            system_role_path(user_id, role_id),
        )
        .await
    }

    /// `HEAD /v4/system/users/{user_id}/roles/{role_id}`.
    pub async fn check_system_role_v4(
        client: &Arc<AsyncOpenStack>,
        user_id: &str,
        role_id: &str,
    ) -> Result<()> {
        ignore_v4(
            client,
            http::Method::HEAD,
            system_role_path(user_id, role_id),
        )
        .await
    }

    /// `DELETE /v4/system/users/{user_id}/roles/{role_id}`.
    pub async fn revoke_system_role_v4(
        client: &Arc<AsyncOpenStack>,
        user_id: &str,
        role_id: &str,
    ) -> Result<()> {
        ignore_v4(
            client,
            http::Method::DELETE,
            system_role_path(user_id, role_id),
        )
        .await
    }

    /// A `GET` returning a collection under `response_key`.
    #[derive(Clone, Debug)]
    struct RoleAssignmentV4ListRequest {
        endpoint: String,
        response_key: &'static str,
    }

    impl RestEndpoint for RoleAssignmentV4ListRequest {
        fn method(&self) -> http::Method {
            http::Method::GET
        }

        fn endpoint(&self) -> Cow<'static, str> {
            self.endpoint.clone().into()
        }

        fn service_type(&self) -> ServiceType {
            ServiceType::Identity
        }

        fn response_key(&self) -> Option<Cow<'static, str>> {
            Some(self.response_key.into())
        }

        fn api_version(&self) -> Option<ApiVersion> {
            Some(ApiVersion::new(4, 0))
        }
    }

    /// `GET /v4/projects/{project_id}/users/{user_id}/roles`.
    pub async fn list_project_roles_v4(
        client: &Arc<AsyncOpenStack>,
        project_id: &str,
        user_id: &str,
    ) -> Result<Vec<Role>> {
        Ok(RoleAssignmentV4ListRequest {
            endpoint: format!("projects/{project_id}/users/{user_id}/roles"),
            response_key: "roles",
        }
        .query_async(client.as_ref())
        .await?)
    }

    /// `GET /v4/system/users/{user_id}/roles`.
    pub async fn list_system_roles_v4(
        client: &Arc<AsyncOpenStack>,
        user_id: &str,
    ) -> Result<Vec<Role>> {
        Ok(RoleAssignmentV4ListRequest {
            endpoint: format!("system/users/{user_id}/roles"),
            response_key: "roles",
        }
        .query_async(client.as_ref())
        .await?)
    }

    /// `GET /v4/role_assignments`.
    pub async fn list_role_assignments_v4(client: &Arc<AsyncOpenStack>) -> Result<Vec<Assignment>> {
        Ok(RoleAssignmentV4ListRequest {
            endpoint: "role_assignments".to_string(),
            response_key: "role_assignments",
        }
        .query_async(client.as_ref())
        .await?)
    }
}
