package com.authguard.adapter.filter;

import com.authguard.adapter.access.AuthguardAccess;
import com.authguard.adapter.model.AuthguardTypes.RequestAccess;
import com.authguard.adapter.util.AuthguardUtils;
import java.util.Arrays;
import java.util.List;

public class AuthguardAccessFilter implements AutoCloseable {
  private final List<AuthguardAccess.IAccessContextResolver> resolvers;

  public AuthguardAccessFilter() {
    this(new AuthguardAccess.HeaderAccessContextResolver());
  }

  public AuthguardAccessFilter(AuthguardAccess.IAccessContextResolver... resolvers) {
    this.resolvers = Arrays.stream(resolvers).filter(resolver -> resolver != null).toList();
  }

  public AccessScope enter(AuthguardAccess.AccessHeaders request) {
    return enterHeadersInternal(
        request.header(AuthguardUtils.ACCESS_CONTEXT_HEADER),
        request.header(AuthguardUtils.SCOPE_TOKEN_HEADER),
        request.header(AuthguardUtils.REQUEST_ID_HEADER));
  }

  public AccessScope enterHeaders(String encodedAccessContext, String scopeToken) {
    return enterHeadersInternal(encodedAccessContext, scopeToken, null);
  }

  private AccessScope enterHeadersInternal(
      String encodedAccessContext, String scopeToken, String requestId) {
    AuthguardAccess.ContextHolder.clear();
    AuthguardUtils.logDebug(
        "authguard.access_filter.started",
        "request_id",
        requestId,
        "direct_context_present",
        hasText(encodedAccessContext),
        "scope_token_present",
        hasText(scopeToken),
        "resolver_count",
        resolvers.size());
    if (hasText(encodedAccessContext) && hasText(scopeToken)) {
      AuthguardUtils.logDebug(
          "authguard.access_filter.rejected",
          "request_id",
          requestId,
          "reason",
          "conflicting_headers");
      throw new SecurityException("both Authguard context and scope token headers are present");
    }
    AuthguardAccess.AccessHeaders headers =
        name -> {
          if (AuthguardUtils.ACCESS_CONTEXT_HEADER.equalsIgnoreCase(name)) {
            return encodedAccessContext;
          }
          if (AuthguardUtils.SCOPE_TOKEN_HEADER.equalsIgnoreCase(name)) {
            return scopeToken;
          }
          return null;
        };
    for (AuthguardAccess.IAccessContextResolver resolver : resolvers) {
      try {
        var resolved = resolver.resolve(headers);
        if (resolved.isPresent()) {
          RequestAccess requestAccess = resolved.get();
          AuthguardAccess.ContextHolder.set(requestAccess);
          AuthguardUtils.logDebug(
              "authguard.access_filter.authenticated",
              "request_id",
              requestId,
              "resolver_mode",
              resolverMode(resolver),
              "principal_id",
              requestAccess.principalId(),
              "action",
              requestAccess.action(),
              "allow_count",
              requestAccess.grants().allowResourceUrns().size(),
              "deny_count",
              requestAccess.grants().denyResourceUrns().size());
          return new AccessScope(true, requestAccess);
        }
      } catch (RuntimeException error) {
        AuthguardUtils.logDebug(
            "authguard.access_filter.rejected",
            "request_id",
            requestId,
            "resolver_mode",
            resolverMode(resolver),
            "reason",
            "resolver_error",
            "error_category",
            AuthguardUtils.errorCategory(error));
        throw error;
      }
    }
    if (hasText(scopeToken)) {
      AuthguardUtils.logDebug(
          "authguard.access_filter.rejected",
          "request_id",
          requestId,
          "reason",
          "scope_resolver_unavailable");
      throw new SecurityException("no resolver is configured for the Authguard scope token");
    }
    AuthguardUtils.logDebug(
        "authguard.access_filter.unauthenticated", "request_id", requestId);
    return new AccessScope(false, null);
  }

  private static String resolverMode(AuthguardAccess.IAccessContextResolver resolver) {
    if (resolver instanceof AuthguardAccess.HeaderAccessContextResolver) {
      return "header";
    }
    if (resolver instanceof AuthguardAccess.GrpcAccessContextResolver) {
      return "grpc";
    }
    return "custom";
  }

  private static boolean hasText(String value) {
    return value != null && !value.isBlank();
  }

  @Override
  public void close() {
    for (AuthguardAccess.IAccessContextResolver resolver : resolvers) {
      if (resolver instanceof AutoCloseable closeable) {
        try {
          closeable.close();
        } catch (Exception error) {
          throw new IllegalStateException("close Authguard access resolver", error);
        }
      }
    }
  }

  public static final class AccessScope implements AutoCloseable {
    private final boolean authenticated;
    private final RequestAccess requestAccess;
    private boolean closed;

    private AccessScope(boolean authenticated, RequestAccess requestAccess) {
      this.authenticated = authenticated;
      this.requestAccess = requestAccess;
    }

    public boolean authenticated() {
      return authenticated;
    }

    public RequestAccess requestAccess() {
      return requestAccess;
    }

    @Override
    public void close() {
      if (!closed) {
        AuthguardAccess.ContextHolder.clear();
        closed = true;
      }
    }
  }
}
