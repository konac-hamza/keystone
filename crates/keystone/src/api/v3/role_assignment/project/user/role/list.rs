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

//! Project user role: list.

use std::ptr::null;

/// List role assignments for user on project.
///
/// List role assignments for a user on a project.
use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
};
use serde_json::json;
use tracing::info;

use openstack_keystone_core_types::assignment::Assignment;
use openstack_keystone_core_types::assignment::RoleAssignmentListParameters;

use crate::api::error::KeystoneApiError;
use crate::api::v3::role_assignment as api_types;
use crate::keystone::ServiceState;
use crate::{
    api::auth::Auth, assignment::AssignmentApi, identity::IdentityApi, resource::ResourceApi,
    role::RoleApi,
};
#[utoipa::path(
    get,
    path = "/projects/{project_id}/users/{user_id}/roles",
    operation_id = "/project/user/role:list",
    params(
      ("project_id" = String, Path, description = "The project ID."),
      ("user_id" = String, Path, description = "The user ID.")
    ),
    responses(
        (status = OK, description = "List of role assignments."),
        (status = 404, description = "Grant not found", example = json!(KeystoneApiError::NotFound(String::from("id = 1"))))
    ),
    security(("x-auth" = [])),
    tag="role_assignments"
)]
#[tracing::instrument(
    name = "api::project_user_role_list",
    level = "debug",
    skip(state, user_auth),
    err(Debug)
)]

pub(super) async fn list(
    Auth(user_auth): Auth,
    Path((project_id, user_id)): Path<(String, String)>,
    State(state): State<ServiceState>,
) -> Result<impl IntoResponse, KeystoneApiError> {
    let query_params = RoleAssignmentListParameters {
        user_id: Some(user_id.clone()),
        project_id: Some(project_id.clone()),
        effective: Some(true),
        include_names: Some(false),
        ..Default::default()
    };

    let (user, project, assignments) = tokio::join!(
        state
            .provider
            .get_identity_provider()
            .get_user(&state, &user_id),
        state
            .provider
            .get_resource_provider()
            .get_project(&state, &project_id),
        state
            .provider
            .get_assignment_provider()
            .list_role_assignments(&state, &query_params)
    );
    let user = user?.ok_or_else(|| {
        info!("User {} was not found", user_id);
        KeystoneApiError::NotFound {
            resource: "grant".into(),
            identifier: "".into(),
        }
    })?;
    let project = project?.ok_or_else(|| {
        info!("Project {} was not found", project_id);
        KeystoneApiError::NotFound {
            resource: "grant".into(),
            identifier: "".into(),
        }
    })?;
    state
        .policy_enforcer
        .enforce(
            "identity/project/user/role/list",
            &user_auth,
            json!({"user": user, "role": null, "project": project}),
            None,
        )
        .await?;
    let grants: Vec<Assignment> = assignments?.into_iter().collect();
    // Convert Assignment to RoleRef
    let role_refs: Vec<api_types::types::Role> = grants.into_iter().map(|a| a.into()).collect();
    Ok((StatusCode::OK, Json(role_refs)).into_response())
}

#[cfg(test)]
mod tests {
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use tower::ServiceExt;
    use tower_http::trace::TraceLayer;
    use tracing_test::traced_test;

    use openstack_keystone_core_types::assignment::*;
    use openstack_keystone_core_types::identity::*;
    use openstack_keystone_core_types::resource::*;

    use crate::api::tests::get_mocked_state;
    use crate::api::v3::role_assignment::openapi_router;
    use crate::assignment::MockAssignmentProvider;
    use crate::identity::MockIdentityProvider;
    use crate::provider::Provider;
    use crate::resource::MockResourceProvider;

    #[tokio::test]
    #[traced_test]
    async fn test_list_found_allowed() {
        let mut identity_mock = MockIdentityProvider::default();
        identity_mock
            .expect_get_user()
            .withf(|_, id: &'_ str| id == "user_id")
            .returning(|_, _| {
                Ok(Some(
                    UserResponseBuilder::default()
                        .id("user_id")
                        .domain_id("user_domain_id")
                        .enabled(true)
                        .name("name")
                        .build()
                        .unwrap(),
                ))
            });
        let mut assignment_mock = MockAssignmentProvider::default();
        assignment_mock
            .expect_list_role_assignments()
            .withf(|_, params: &RoleAssignmentListParameters| {
                params.user_id.as_ref().is_some_and(|x| x == "user_id")
                    && params
                        .project_id
                        .as_ref()
                        .is_some_and(|x| x == "project_id")
                    && params.effective.is_some_and(|x| x)
            })
            .returning(|_, _| {
                Ok(vec![Assignment {
                    role_id: "role_id".into(),
                    role_name: Some("rn".into()),
                    actor_id: "user_id".into(),
                    target_id: "project_id".into(),
                    r#type: AssignmentType::UserProject,
                    inherited: false,
                    implied_via: None,
                }])
            });
        let mut resource_mock = MockResourceProvider::default();
        resource_mock
            .expect_get_project()
            .withf(|_, pid: &'_ str| pid == "project_id")
            .returning(|_, id: &'_ str| {
                Ok(Some(Project {
                    id: id.to_string(),
                    domain_id: "project_domain_id".into(),
                    ..Default::default()
                }))
            });
        let provider_builder = Provider::mocked_builder()
            .mock_assignment(assignment_mock)
            .mock_identity(identity_mock)
            .mock_resource(resource_mock);
        let state = get_mocked_state(provider_builder, true, None, None).await;
        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state.clone());

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/projects/project_id/users/user_id/roles")
                    .header("x-auth-token", "foo")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    #[traced_test]
    async fn test_list_empty_allowed() {
        let mut identity_mock = MockIdentityProvider::default();
        identity_mock
            .expect_get_user()
            .withf(|_, id: &'_ str| id == "user_id")
            .returning(|_, _| {
                Ok(Some(
                    UserResponseBuilder::default()
                        .id("user_id")
                        .domain_id("user_domain_id")
                        .enabled(true)
                        .name("name")
                        .build()
                        .unwrap(),
                ))
            });
        let mut assignment_mock = MockAssignmentProvider::default();
        assignment_mock
            .expect_list_role_assignments()
            .returning(|_, _| Ok(vec![]));
        let mut resource_mock = MockResourceProvider::default();
        resource_mock
            .expect_get_project()
            .withf(|_, pid: &'_ str| pid == "project_id")
            .returning(|_, id: &'_ str| {
                Ok(Some(Project {
                    id: id.to_string(),
                    domain_id: "project_domain_id".into(),
                    ..Default::default()
                }))
            });
        let provider_builder = Provider::mocked_builder()
            .mock_assignment(assignment_mock)
            .mock_identity(identity_mock)
            .mock_resource(resource_mock);
        let state = get_mocked_state(provider_builder, true, None, None).await;
        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state.clone());

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/projects/project_id/users/user_id/roles")
                    .header("x-auth-token", "foo")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    #[traced_test]
    async fn test_list_not_allowed() {
        let mut identity_mock = MockIdentityProvider::default();
        identity_mock.expect_get_user().returning(|_, _| {
            Ok(Some(
                UserResponseBuilder::default()
                    .id("user_id")
                    .domain_id("user_domain_id")
                    .enabled(true)
                    .name("name")
                    .build()
                    .unwrap(),
            ))
        });
        let mut assignment_mock = MockAssignmentProvider::default();
        assignment_mock
            .expect_list_role_assignments()
            .returning(|_, _| Ok(vec![]));
        let mut resource_mock = MockResourceProvider::default();
        resource_mock
            .expect_get_project()
            .returning(|_, id: &'_ str| {
                Ok(Some(Project {
                    id: id.to_string(),
                    domain_id: "project_domain_id".into(),
                    ..Default::default()
                }))
            });
        let provider_builder = Provider::mocked_builder()
            .mock_assignment(assignment_mock)
            .mock_identity(identity_mock)
            .mock_resource(resource_mock);
        let state = get_mocked_state(provider_builder, false, None, None).await;
        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state.clone());

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/projects/project_id/users/user_id/roles")
                    .header("x-auth-token", "foo")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    #[traced_test]
    async fn test_list_user_not_found() {
        let mut identity_mock = MockIdentityProvider::default();
        identity_mock.expect_get_user().returning(|_, _| Ok(None));
        let mut assignment_mock = MockAssignmentProvider::default();
        assignment_mock
            .expect_list_role_assignments()
            .returning(|_, _| Ok(vec![]));
        let mut resource_mock = MockResourceProvider::default();
        resource_mock
            .expect_get_project()
            .returning(|_, id: &'_ str| {
                Ok(Some(Project {
                    id: id.to_string(),
                    domain_id: "project_domain_id".into(),
                    ..Default::default()
                }))
            });
        let provider_builder = Provider::mocked_builder()
            .mock_assignment(assignment_mock)
            .mock_identity(identity_mock)
            .mock_resource(resource_mock);
        let state = get_mocked_state(provider_builder, true, None, None).await;
        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state.clone());

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/projects/project_id/users/user_id/roles")
                    .header("x-auth-token", "foo")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    #[traced_test]
    async fn test_list_project_not_found() {
        let mut identity_mock = MockIdentityProvider::default();
        identity_mock.expect_get_user().returning(|_, _| {
            Ok(Some(
                UserResponseBuilder::default()
                    .id("user_id")
                    .domain_id("user_domain_id")
                    .enabled(true)
                    .name("name")
                    .build()
                    .unwrap(),
            ))
        });
        let mut assignment_mock = MockAssignmentProvider::default();
        assignment_mock
            .expect_list_role_assignments()
            .returning(|_, _| Ok(vec![]));
        let mut resource_mock = MockResourceProvider::default();
        resource_mock
            .expect_get_project()
            .returning(|_, _| Ok(None));
        let provider_builder = Provider::mocked_builder()
            .mock_assignment(assignment_mock)
            .mock_identity(identity_mock)
            .mock_resource(resource_mock);
        let state = get_mocked_state(provider_builder, true, None, None).await;
        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state.clone());

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/projects/project_id/users/user_id/roles")
                    .header("x-auth-token", "foo")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }
}
