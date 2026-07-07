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
use crate::api_v3::identity::application_credential::list::get_project_scoped_client;
use eyre::Result;
use openstack_keystone_api_types::v3::application_credential::application_credential::*;
use openstack_keystone_api_types::v3::user::*;
use openstack_sdk::{AsyncOpenStack, config::CloudConfig};
use std::sync::Arc;
use test_api::guard::ResourceGuard;
use test_api::identity::application_credential::{
    create_application_credential, get_application_credential,
};
use test_api::identity::user::create_user;
use tracing_test::traced_test;
use uuid::Uuid;

// async fn get_project_scoped_client() -> Result<Arc<AsyncOpenStack>> {
//     let mut tc = AsyncOpenStack::new(&CloudConfig::from_env()?).await?;

//     tc.authorize(
//         Some(openstack_sdk::auth::authtoken::AuthTokenScope::Project(
//             openstack_sdk::types::identity::v3::Project {
//                 id: None,
//                 name: Some("admin".to_string()),
//                 domain: Some(openstack_sdk::types::identity::v3::Domain {
//                     id: Some("default".to_string()),
//                     name: None,
//                 }),
//             },
//         )),
//         false,
//         false,
//     ).await?;

//     Ok(Arc::new(tc))
// }

#[tokio::test]
#[traced_test]
async fn test_show() -> Result<()> {
    let tc = get_project_scoped_client().await?;
    let user_id = tc
        .get_auth_info()
        .ok_or_else(|| eyre::eyre!("no auth info available"))?
        .token
        .user
        .id;

    let cred = create_application_credential(
        &tc,
        &user_id,
        ApplicationCredentialCreateBuilder::default()
            .name("test-cred")
            .roles(vec![])
            .build()?,
    )
    .await?;

    let fetched = get_application_credential(&tc, &user_id, &cred.id).await?;

    assert_eq!(fetched.id, cred.id);
    assert_eq!(fetched.name, "test-cred");
    assert_eq!(fetched.user_id, user_id);

    cred.delete().await?;
    Ok(())
}
