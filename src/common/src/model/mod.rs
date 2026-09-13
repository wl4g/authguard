//! Protocol-neutral IAM domain model.

pub mod credential;
pub mod identity;
pub mod policy;
pub mod principal;
pub mod role;

pub use crate::utils::{
    access_context_v1, epoch_seconds, AccessContext, AccessContextError, AccessContextInput,
    AccessContextSigner, AuthorizationConditionSpec, AuthorizationConditions, EvaluationContext,
    PathMap, PathPattern, RequestConditionSpec, ResourceSqlMapping, ResourceUrn, SegmentMap,
    SegmentPattern, SourceIpConditionSpec, SqlCompileError, SqlScope, SubjectConditionSpec,
    UrnError, UrnPattern, ACCESS_CONTEXT_HEADER, ACCESS_CONTEXT_SIGNING_KEY_ENV,
    ACCESS_CONTEXT_VERSION, SCOPE_TOKEN_HEADER,
};
pub use credential::{
    CredentialModelError, IamStandaloneCredential, StandaloneCredentialIdentity,
    StandaloneCredentialKind,
};
pub use identity::{
    AuthenticatedPrincipalContext, AuthenticationResult, ExternalIdentity, ExternalIdentityKey,
    IdentityError, IdentityModelError,
};
pub use policy::IamPolicyInfo;
pub use principal::{IamPrincipalIdentityInfo, IamPrincipalInfo, PrincipalKind, PrincipalStatus};
pub use role::{
    AuthorizationDecision, AuthorizationRequest, AuthorizationScope, Effect, HttpRouteMatcher,
    IamActionInfo, IamRoleBindingInfo, IamRoleInfo,
};
