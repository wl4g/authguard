package com.authguard.adapter.filter;

import com.authguard.adapter.access.AuthguardAccess;
import com.authguard.adapter.util.AuthguardUtils;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.web.servlet.HandlerInterceptor;

public final class AuthguardAccessInterceptor implements HandlerInterceptor, AutoCloseable {
  private static final String ACCESS_SCOPE_ATTRIBUTE =
      AuthguardAccessInterceptor.class.getName() + ".ACCESS_SCOPE";

  private final AuthguardAccessFilter accessFilter;

  public AuthguardAccessInterceptor() {
    this(new AuthguardAccessFilter());
  }

  public AuthguardAccessInterceptor(AuthguardAccess.IAccessContextResolver... resolvers) {
    this(new AuthguardAccessFilter(resolvers));
  }

  public AuthguardAccessInterceptor(AuthguardAccessFilter accessFilter) {
    this.accessFilter = accessFilter;
  }

  @Override
  public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) {
    try {
      AuthguardAccessFilter.AccessScope scope = accessFilter.enter(request::getHeader);
      if (!scope.authenticated()) {
        scope.close();
        AuthguardUtils.logDebug(
            "authguard.http_filter.rejected",
            "request_id",
            request.getHeader(AuthguardUtils.REQUEST_ID_HEADER),
            "http_method",
            request.getMethod(),
            "reason",
            "access_context_missing");
        response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Authguard context is required");
        return false;
      }
      request.setAttribute(ACCESS_SCOPE_ATTRIBUTE, scope);
      AuthguardUtils.logDebug(
          "authguard.http_filter.accepted",
          "request_id",
          request.getHeader(AuthguardUtils.REQUEST_ID_HEADER),
          "http_method",
          request.getMethod(),
          "principal_id",
          scope.requestAccess().principalId(),
          "action",
          scope.requestAccess().action());
      return true;
    } catch (RuntimeException | java.io.IOException error) {
      AuthguardAccess.ContextHolder.clear();
      AuthguardUtils.logDebug(
          "authguard.http_filter.rejected",
          "request_id",
          request.getHeader(AuthguardUtils.REQUEST_ID_HEADER),
          "http_method",
          request.getMethod(),
          "reason",
          "invalid_access_context",
          "error_category",
          AuthguardUtils.errorCategory(error));
      try {
        response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Invalid Authguard context");
      } catch (java.io.IOException responseError) {
        error.addSuppressed(responseError);
      }
      return false;
    }
  }

  @Override
  public void afterCompletion(
      HttpServletRequest request, HttpServletResponse response, Object handler, Exception ex) {
    Object scope = request.getAttribute(ACCESS_SCOPE_ATTRIBUTE);
    if (scope instanceof AuthguardAccessFilter.AccessScope accessScope) {
      accessScope.close();
      request.removeAttribute(ACCESS_SCOPE_ATTRIBUTE);
    } else {
      AuthguardAccess.ContextHolder.clear();
    }
    AuthguardUtils.logDebug(
        "authguard.http_filter.completed",
        "request_id",
        request.getHeader(AuthguardUtils.REQUEST_ID_HEADER),
        "http_method",
        request.getMethod(),
        "http_status",
        response.getStatus(),
        "error_category",
        ex == null ? "none" : AuthguardUtils.errorCategory(ex));
  }

  @Override
  public void close() {
    accessFilter.close();
  }
}
