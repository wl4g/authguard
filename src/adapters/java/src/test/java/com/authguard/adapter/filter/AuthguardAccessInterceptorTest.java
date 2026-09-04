package com.authguard.adapter.filter;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.authguard.adapter.access.AuthguardAccess;
import com.authguard.adapter.model.AuthguardTypes.AccessContext;
import com.authguard.adapter.model.AuthguardTypes.RequestAccess;
import com.authguard.adapter.util.AuthguardUtils;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

class AuthguardAccessInterceptorTest {
  private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();
  private static final String TEST_SIGNING_KEY =
      "test-access-context-hmac-key-32-bytes-minimum";

  @AfterEach
  void clearContext() {
    AuthguardAccess.ContextHolder.clear();
  }

  @Test
  void headerContextResolverSetsRequestAccess() {
    try (var scope =
        directFilter().enterHeaders(signedContext(), null)) {
      assertAuthenticated(scope.requestAccess());
    }

    assertTrue(AuthguardAccess.ContextHolder.getAccess().isEmpty());
  }

  @Test
  void grpcContextResolverResolvesOpaqueToken() {
    AtomicReference<String> resolvedToken = new AtomicReference<>();
    AuthguardAccess.ScopeTokenClient client =
        token -> {
          resolvedToken.set(token);
          return AuthguardUtils.encodeAccessContext(sampleContext());
        };
    var filter =
        new AuthguardAccessFilter(new AuthguardAccess.GrpcAccessContextResolver(client));

    try (var scope = filter.enterHeaders(null, "ags_scope")) {
      assertAuthenticated(scope.requestAccess());
    }

    assertEquals("ags_scope", resolvedToken.get());
  }

  @Test
  void missingAccessHeadersRemainUnauthenticated() {
    AuthguardAccess.ContextHolder.set(sampleContext().requestAccess());

    try (var scope = new AuthguardAccessFilter().enterHeaders(null, null)) {
      assertFalse(scope.authenticated());
      assertTrue(AuthguardAccess.ContextHolder.getAccess().isEmpty());
    }
  }

  @Test
  void malformedDirectContextFailsClosed() {
    assertThrows(
        IllegalArgumentException.class,
        () -> directFilter().enterHeaders("not-base64!", null));

    assertTrue(AuthguardAccess.ContextHolder.getAccess().isEmpty());
  }

  @Test
  void unsupportedDirectContextVersionFailsClosed() {
    AccessContext context = sampleContext();
    AccessContext unsupported =
        new AccessContext(
            1,
            context.principalId(),
            context.action(),
            context.resourceUrn(),
            context.allowResourceUrns(),
            context.denyResourceUrns(),
            context.policyRevision(),
            context.issuedAtEpochSeconds(),
            context.expiresAtEpochSeconds());

    assertThrows(
        IllegalArgumentException.class,
        () -> directFilter().enterHeaders(signUnchecked(unsupported), null));
  }

  @Test
  void expiredDirectContextFailsClosed() {
    AccessContext context = sampleContext();
    AccessContext expired =
        new AccessContext(
            3,
            context.principalId(),
            context.action(),
            context.resourceUrn(),
            context.allowResourceUrns(),
            context.denyResourceUrns(),
            context.policyRevision(),
            1,
            2);

    assertThrows(
        IllegalArgumentException.class,
        () -> directFilter().enterHeaders(signUnchecked(expired), null));
  }

  @Test
  void conflictingContextAndTokenHeadersFailClosed() {
    assertThrows(
        SecurityException.class,
        () ->
            directFilter().enterHeaders(signedContext(), "ags_scope"));
  }

  @Test
  void scopeResolverFailureFailsClosed() {
    AuthguardAccess.ScopeTokenClient client =
        token -> {
          throw new IllegalStateException("scope service unavailable");
        };

    assertThrows(
        IllegalStateException.class,
        () ->
            new AuthguardAccessFilter(
                    new AuthguardAccess.GrpcAccessContextResolver(client))
                .enterHeaders(null, "ags_scope"));
  }

  @Test
  void scopeTokenWithoutRequestResolverFailsClosed() {
    assertThrows(
        SecurityException.class,
        () -> new AuthguardAccessFilter().enterHeaders(null, "ags_scope"));
  }

  @Test
  void malformedResolvedContextFailsClosed() {
    AuthguardAccess.ScopeTokenClient client = token -> "not-base64!";

    assertThrows(
        IllegalArgumentException.class,
        () ->
            new AuthguardAccessFilter(
                    new AuthguardAccess.GrpcAccessContextResolver(client))
                .enterHeaders(null, "ags_scope"));
  }

  @Test
  void directContextDoesNotCallScopeService() {
    AtomicBoolean called = new AtomicBoolean();
    AuthguardAccess.ScopeTokenClient client =
        token -> {
          called.set(true);
          throw new AssertionError("scope service must not be called");
        };
    var filter =
        new AuthguardAccessFilter(
            new AuthguardAccess.HeaderAccessContextResolver(TEST_SIGNING_KEY),
            new AuthguardAccess.GrpcAccessContextResolver(client));

    try (var scope =
        filter.enterHeaders(signedContext(), null)) {
      assertAuthenticated(scope.requestAccess());
    }

    assertFalse(called.get());
  }

  @Test
  void secondEntryDoesNotReusePreviousRequestAccess() {
    var filter = directFilter();
    var first = filter.enterHeaders(signedContext(), null);
    assertTrue(AuthguardAccess.ContextHolder.getAccess().isPresent());

    try (var second = filter.enterHeaders(null, null)) {
      assertFalse(second.authenticated());
      assertTrue(AuthguardAccess.ContextHolder.getAccess().isEmpty());
    } finally {
      first.close();
    }
  }

  @Test
  void frameworkAdapterScopesDirectContextToRequest() {
    var interceptor = directInterceptor();
    var request = new MockHttpServletRequest();
    request.addHeader(
        AuthguardUtils.ACCESS_CONTEXT_HEADER, signedContext());
    var response = new MockHttpServletResponse();

    assertTrue(interceptor.preHandle(request, response, new Object()));
    assertAuthenticated(AuthguardAccess.ContextHolder.requireAccess());

    interceptor.afterCompletion(request, response, new Object(), null);
    assertTrue(AuthguardAccess.ContextHolder.getAccess().isEmpty());
  }

  @Test
  void frameworkAdapterRejectsMissingAccessContext() {
    var interceptor = new AuthguardAccessInterceptor();
    var response = new MockHttpServletResponse();

    assertFalse(interceptor.preHandle(new MockHttpServletRequest(), response, new Object()));

    assertEquals(401, response.getStatus());
    assertTrue(AuthguardAccess.ContextHolder.getAccess().isEmpty());
  }

  @Test
  void frameworkAdapterResolvesScopeToken() {
    AtomicReference<String> resolvedToken = new AtomicReference<>();
    AuthguardAccess.ScopeTokenClient client =
        token -> {
          resolvedToken.set(token);
          return AuthguardUtils.encodeAccessContext(sampleContext());
        };
    var interceptor =
        new AuthguardAccessInterceptor(new AuthguardAccess.GrpcAccessContextResolver(client));
    var request = new MockHttpServletRequest();
    request.addHeader(AuthguardUtils.SCOPE_TOKEN_HEADER, "ags_scope");
    var response = new MockHttpServletResponse();

    assertTrue(interceptor.preHandle(request, response, new Object()));
    assertAuthenticated(AuthguardAccess.ContextHolder.requireAccess());
    assertEquals("ags_scope", resolvedToken.get());

    interceptor.afterCompletion(request, response, new Object(), null);
  }

  @Test
  void grpcTargetConfigurationUsesStandardEnvironmentNames() {
    assertEquals("AUTHGUARD_GRPC_TARGET", AuthguardAccess.GRPC_TARGET_ENV);
    assertEquals("AUTHGUARD_GRPC_TLS", AuthguardAccess.GRPC_TLS_ENV);
  }

  @Test
  void grpcClientAcceptsExplicitInternalTargetWithoutConnecting() {
    try (var client =
        new AuthguardAccess.GrpcScopeTokenClient(
            "authguard.authguard.svc.cluster.local:8080")) {
      assertFalse(client.toString().isBlank());
    }
  }

  @Test
  void grpcClientInitializesFromEnvironmentWithoutConnecting() throws Exception {
    String javaExecutable =
        Path.of(System.getProperty("java.home"), "bin", "java").toString();
    String classpath =
        System.getProperty("surefire.test.class.path", System.getProperty("java.class.path"));
    ProcessBuilder builder =
        new ProcessBuilder(javaExecutable, "-cp", classpath, EnvironmentProbe.class.getName())
            .redirectErrorStream(true);
    builder.environment().put(AuthguardAccess.GRPC_TARGET_ENV, "authguard.internal:8080");
    builder.environment().put(AuthguardAccess.GRPC_TLS_ENV, "false");
    builder.environment().put(AuthguardAccess.ACCESS_CONTEXT_HMAC_KEY_ENV, TEST_SIGNING_KEY);

    Process process = builder.start();
    String output =
        new String(process.getInputStream().readAllBytes(), StandardCharsets.UTF_8);

    assertEquals(0, process.waitFor(), output);
  }

  @Test
  void unsignedDirectContextFailsClosed() {
    assertThrows(
        IllegalArgumentException.class,
        () -> directFilter().enterHeaders(AuthguardUtils.encodeAccessContext(sampleContext()), null));
  }

  @Test
  void tamperedDirectContextFailsClosed() {
    String tampered = signedContext().replaceFirst("agctx1\\.", "agctx1.A");
    assertThrows(
        IllegalArgumentException.class, () -> directFilter().enterHeaders(tampered, null));
  }

  @Test
  void directContextSignedWithDifferentKeyFailsClosed() {
    String signed =
        AuthguardUtils.signAccessContext(
            sampleContext(), "different-access-context-hmac-key-32-bytes-minimum");
    assertThrows(
        IllegalArgumentException.class, () -> directFilter().enterHeaders(signed, null));
  }

  @Test
  void signingKeyConfigurationUsesStandardEnvironmentName() {
    assertEquals(
        "AUTHGUARD_ACCESS_CONTEXT_HMAC_KEY", AuthguardAccess.ACCESS_CONTEXT_HMAC_KEY_ENV);
  }

  private static void assertAuthenticated(RequestAccess requestAccess) {
    assertEquals("revenue-analyst", requestAccess.principalId());
    assertEquals("customer-growth.job.read", requestAccess.action());
    assertEquals(requestAccess, AuthguardAccess.ContextHolder.requireAccess());
  }

  private static String encodeUnchecked(AccessContext context) {
    try {
      return Base64.getUrlEncoder()
          .withoutPadding()
          .encodeToString(OBJECT_MAPPER.writeValueAsBytes(context));
    } catch (Exception error) {
      throw new IllegalStateException(error);
    }
  }

  private static String signUnchecked(AccessContext context) {
    return AuthguardUtils.signEncodedAccessContext(encodeUnchecked(context), TEST_SIGNING_KEY);
  }

  private static String signedContext() {
    return AuthguardUtils.signAccessContext(sampleContext(), TEST_SIGNING_KEY);
  }

  private static AuthguardAccessFilter directFilter() {
    return new AuthguardAccessFilter(
        new AuthguardAccess.HeaderAccessContextResolver(TEST_SIGNING_KEY));
  }

  private static AuthguardAccessInterceptor directInterceptor() {
    return new AuthguardAccessInterceptor(
        new AuthguardAccess.HeaderAccessContextResolver(TEST_SIGNING_KEY));
  }

  private static AccessContext sampleContext() {
    long now = Instant.now().getEpochSecond();
    return new AccessContext(
        3,
        "revenue-analyst",
        "customer-growth.job.read",
        "urn:iam:prod:customer-growth:global:example-corp:workspace/customer-insights/project/retention-analytics/job/daily-churn-risk-score",
        List.of(
            "urn:iam:prod:customer-growth:global:example-corp:workspace/customer-insights/project/retention-analytics/job/*"),
        List.of(
            "urn:iam:prod:customer-growth:global:example-corp:workspace/customer-insights/project/retention-analytics/job/vip-retention-risk-audit"),
        1,
        now,
        now + 30);
  }

  public static final class EnvironmentProbe {
    private EnvironmentProbe() {}

    public static void main(String[] args) {
      AuthguardAccess.HeaderAccessContextResolver.fromEnvironment();
      try (var client = AuthguardAccess.GrpcScopeTokenClient.fromEnvironment()) {
        if (client.toString().isBlank()) {
          throw new IllegalStateException("gRPC client was not initialized");
        }
      }
    }
  }
}
