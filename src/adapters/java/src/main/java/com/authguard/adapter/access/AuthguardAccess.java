package com.authguard.adapter.access;

import com.authguard.adapter.model.AuthguardTypes.AccessContext;
import com.authguard.adapter.model.AuthguardTypes.AccessGrantSet;
import com.authguard.adapter.model.AuthguardTypes.RequestAccess;
import com.authguard.adapter.util.AuthguardUtils;
import com.google.protobuf.StringValue;
import io.grpc.CallOptions;
import io.grpc.ManagedChannel;
import io.grpc.ManagedChannelBuilder;
import io.grpc.MethodDescriptor;
import io.grpc.protobuf.ProtoUtils;
import io.grpc.stub.ClientCalls;
import java.util.Objects;
import java.util.Optional;

public final class AuthguardAccess {
  public static final String GRPC_TARGET_ENV = "AUTHGUARD_GRPC_TARGET";
  public static final String GRPC_TLS_ENV = "AUTHGUARD_GRPC_TLS";
  public static final String ACCESS_CONTEXT_HMAC_KEY_ENV = "AUTHGUARD_ACCESS_CONTEXT_HMAC_KEY";

  private AuthguardAccess() {}

  public static boolean isGrpcTargetConfigured() {
    String target = System.getenv(GRPC_TARGET_ENV);
    return target != null && !target.isBlank();
  }

  @FunctionalInterface
  public interface AccessHeaders {
    String header(String name);
  }

  @FunctionalInterface
  public interface IAccessContextResolver {
    Optional<RequestAccess> resolve(AccessHeaders headers);
  }

  @FunctionalInterface
  public interface ScopeTokenClient extends AutoCloseable {
    String resolveScope(String token);

    @Override
    default void close() {}
  }

  public static final class GrpcScopeTokenClient implements ScopeTokenClient {
    private static final MethodDescriptor<StringValue, StringValue> RESOLVE_SCOPE_METHOD =
        MethodDescriptor.<StringValue, StringValue>newBuilder()
            .setType(MethodDescriptor.MethodType.UNARY)
            .setFullMethodName(
                MethodDescriptor.generateFullMethodName(
                    "authguard.access.v1.AccessContextService", "ResolveScope"))
            .setRequestMarshaller(ProtoUtils.marshaller(StringValue.getDefaultInstance()))
            .setResponseMarshaller(ProtoUtils.marshaller(StringValue.getDefaultInstance()))
            .build();

    private final ManagedChannel channel;

    public GrpcScopeTokenClient(String target) {
      this(target, false);
    }

    public GrpcScopeTokenClient(String target, boolean tls) {
      this(buildChannel(target, tls));
      AuthguardUtils.logDebug(
          "authguard.scope_token.grpc.configured", "resolver_mode", "grpc", "tls", tls);
    }

    public static GrpcScopeTokenClient fromEnvironment() {
      String target = requiredEnvironment(GRPC_TARGET_ENV);
      boolean tls = booleanEnvironment(GRPC_TLS_ENV, false);
      return new GrpcScopeTokenClient(target, tls);
    }

    public GrpcScopeTokenClient(ManagedChannel channel) {
      this.channel = Objects.requireNonNull(channel, "channel");
    }

    @Override
    public String resolveScope(String token) {
      long started = System.nanoTime();
      AuthguardUtils.logDebug(
          "authguard.scope_token.grpc.started", "resolver_mode", "grpc");
      try {
        StringValue response =
            ClientCalls.blockingUnaryCall(
                channel,
                RESOLVE_SCOPE_METHOD,
                CallOptions.DEFAULT,
                StringValue.of(Objects.requireNonNull(token, "token")));
        AuthguardUtils.logDebug(
            "authguard.scope_token.grpc.succeeded",
            "resolver_mode",
            "grpc",
            "duration_ms",
            elapsedMillis(started));
        return response.getValue();
      } catch (RuntimeException error) {
        AuthguardUtils.logWarn(
            "authguard.scope_token.grpc.failed",
            "resolver_mode",
            "grpc",
            "error_category",
            AuthguardUtils.errorCategory(error),
            "duration_ms",
            elapsedMillis(started));
        throw error;
      }
    }

    @Override
    public void close() {
      channel.shutdown();
    }
  }

  /** Decodes the trusted access context injected by Envoy. */
  public static final class HeaderAccessContextResolver implements IAccessContextResolver {
    private final String signingKey;

    public HeaderAccessContextResolver() {
      this.signingKey = null;
    }

    public HeaderAccessContextResolver(String signingKey) {
      AuthguardUtils.signEncodedAccessContext("probe", signingKey);
      this.signingKey = signingKey;
    }

    public static HeaderAccessContextResolver fromEnvironment() {
      return new HeaderAccessContextResolver(requiredSecretEnvironment(ACCESS_CONTEXT_HMAC_KEY_ENV));
    }

    @Override
    public Optional<RequestAccess> resolve(AccessHeaders headers) {
      String encoded = headers.header(AuthguardUtils.ACCESS_CONTEXT_HEADER);
      if (encoded == null || encoded.isBlank()) {
        return Optional.empty();
      }
      AuthguardUtils.logDebug(
          "authguard.access_context.header.started", "resolver_mode", "header");
      String key =
          signingKey == null ? requiredSecretEnvironment(ACCESS_CONTEXT_HMAC_KEY_ENV) : signingKey;
      AccessContext context = AuthguardUtils.verifySignedAccessContext(encoded, key);
      RequestAccess requestAccess = context.requestAccess();
      AuthguardUtils.logDebug(
          "authguard.access_context.header.succeeded",
          "resolver_mode",
          "header",
          "principal_id",
          requestAccess.principalId(),
          "action",
          requestAccess.action(),
          "allow_count",
          requestAccess.grants().allowResourceUrns().size(),
          "deny_count",
          requestAccess.grants().denyResourceUrns().size());
      return Optional.of(requestAccess);
    }
  }

  /** Exchanges an opaque request scope token for the complete context through Authguard gRPC. */
  public static final class GrpcAccessContextResolver
      implements IAccessContextResolver, AutoCloseable {
    private final ScopeTokenClient client;

    public GrpcAccessContextResolver(ScopeTokenClient client) {
      this.client = Objects.requireNonNull(client, "client");
    }

    public static GrpcAccessContextResolver fromEnvironment() {
      return new GrpcAccessContextResolver(GrpcScopeTokenClient.fromEnvironment());
    }

    @Override
    public Optional<RequestAccess> resolve(AccessHeaders headers) {
      String token = headers.header(AuthguardUtils.SCOPE_TOKEN_HEADER);
      if (token == null || token.isBlank()) {
        return Optional.empty();
      }
      long started = System.nanoTime();
      AuthguardUtils.logDebug(
          "authguard.access_context.grpc.started", "resolver_mode", "grpc");
      AccessContext context = AuthguardUtils.decodeAccessContext(client.resolveScope(token));
      RequestAccess requestAccess = context.requestAccess();
      AuthguardUtils.logDebug(
          "authguard.access_context.grpc.succeeded",
          "resolver_mode",
          "grpc",
          "principal_id",
          requestAccess.principalId(),
          "action",
          requestAccess.action(),
          "allow_count",
          requestAccess.grants().allowResourceUrns().size(),
          "deny_count",
          requestAccess.grants().denyResourceUrns().size(),
          "duration_ms",
          elapsedMillis(started));
      return Optional.of(requestAccess);
    }

    @Override
    public void close() {
      client.close();
    }
  }

  private static String requiredEnvironment(String name) {
    String value = System.getenv(name);
    if (value == null || value.isBlank()) {
      throw new IllegalStateException(name + " is required");
    }
    return value.trim();
  }

  private static String requiredSecretEnvironment(String name) {
    String value = System.getenv(name);
    if (value == null || value.isEmpty()) {
      throw new IllegalStateException(name + " is required");
    }
    return value;
  }

  private static ManagedChannel buildChannel(String target, boolean tls) {
    ManagedChannelBuilder<?> builder = ManagedChannelBuilder.forTarget(target);
    return (tls ? builder.useTransportSecurity() : builder.usePlaintext()).build();
  }

  private static boolean booleanEnvironment(String name, boolean defaultValue) {
    String value = System.getenv(name);
    if (value == null || value.isBlank()) {
      return defaultValue;
    }
    if ("true".equalsIgnoreCase(value)
        || "1".equals(value)
        || "yes".equalsIgnoreCase(value)
        || "on".equalsIgnoreCase(value)) {
      return true;
    }
    if ("false".equalsIgnoreCase(value)
        || "0".equals(value)
        || "no".equalsIgnoreCase(value)
        || "off".equalsIgnoreCase(value)) {
      return false;
    }
    throw new IllegalStateException(name + " must be a boolean");
  }

  public static final class ContextHolder {
    private static final ThreadLocal<RequestAccess> CURRENT = new ThreadLocal<>();

    private ContextHolder() {}

    public static void set(AccessGrantSet grants) {
      CURRENT.set(RequestAccess.fromGrants(grants));
    }

    public static Optional<AccessGrantSet> get() {
      return getAccess().map(RequestAccess::grants);
    }

    public static AccessGrantSet require() {
      return get()
          .orElseThrow(
              () -> {
                AuthguardUtils.logDebug("authguard.access_context.required_missing");
                return new IllegalStateException("Authguard access context is not available");
              });
    }

    public static void set(RequestAccess requestAccess) {
      CURRENT.set(requestAccess);
      AuthguardUtils.logDebug(
          "authguard.access_context.bound",
          "principal_id",
          requestAccess.principalId(),
          "action",
          requestAccess.action(),
          "allow_count",
          requestAccess.grants().allowResourceUrns().size(),
          "deny_count",
          requestAccess.grants().denyResourceUrns().size());
    }

    public static Optional<RequestAccess> getAccess() {
      return Optional.ofNullable(CURRENT.get());
    }

    public static RequestAccess requireAccess() {
      return getAccess()
          .orElseThrow(
              () -> {
                AuthguardUtils.logDebug("authguard.access_context.required_missing");
                return new IllegalStateException("Authguard access context is not available");
              });
    }

    public static void clear() {
      RequestAccess current = CURRENT.get();
      CURRENT.remove();
      if (current != null) {
        AuthguardUtils.logDebug(
            "authguard.access_context.cleared",
            "principal_id",
            current.principalId(),
            "action",
            current.action());
      }
    }
  }

  private static long elapsedMillis(long startedNanos) {
    return (System.nanoTime() - startedNanos) / 1_000_000;
  }
}
