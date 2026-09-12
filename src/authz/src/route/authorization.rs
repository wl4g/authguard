use envoy_types::ext_authz::v3::pb::AuthorizationServer;

use crate::config::ServerProperties;
use crate::handler::IAuthorizationHandler;
use crate::model::access_context_v1::access_context_service_server::AccessContextServiceServer;

pub struct EnvoyAuthzRoutes<H: IAuthorizationHandler> {
    handler: H,
    max_request_bytes: usize,
    max_response_bytes: usize,
}

impl<H: IAuthorizationHandler> EnvoyAuthzRoutes<H> {
    #[must_use]
    pub fn new(handler: H, config: &ServerProperties) -> Self {
        Self {
            handler,
            max_request_bytes: config.request.max_message_bytes,
            max_response_bytes: config.response.max_message_bytes,
        }
    }

    #[must_use]
    pub fn authorization_service(&self) -> AuthorizationServer<H> {
        AuthorizationServer::new(self.handler.clone())
            .max_decoding_message_size(self.max_request_bytes)
            .max_encoding_message_size(self.max_response_bytes)
    }

    #[must_use]
    pub fn access_context_service(&self) -> AccessContextServiceServer<H> {
        AccessContextServiceServer::new(self.handler.clone())
            .max_decoding_message_size(self.max_request_bytes)
            .max_encoding_message_size(self.max_response_bytes)
    }
}
