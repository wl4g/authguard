package com.authguard.adapter.util;

import static com.authguard.adapter.model.AuthguardTypes.ACCESS_CONTEXT_VERSION;

import com.authguard.adapter.access.AuthguardAccess;
import com.authguard.adapter.model.AuthguardTypes.AccessContext;
import com.authguard.adapter.model.AuthguardTypes.AccessGrantSet;
import com.authguard.adapter.model.AuthguardTypes.PathMap;
import com.authguard.adapter.model.AuthguardTypes.ResourceSqlMapping;
import com.authguard.adapter.model.AuthguardTypes.RequestAccess;
import com.authguard.adapter.model.AuthguardTypes.SegmentMap;
import com.authguard.adapter.model.AuthguardTypes.SqlScope;
import com.authguard.adapter.model.AuthguardTypes.UrnPattern;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.time.Instant;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.StringJoiner;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public final class AuthguardUtils {
  public static final String ACCESS_CONTEXT_HEADER = "x-authguard-context";
  public static final String SCOPE_TOKEN_HEADER = "x-authguard-scope-token";
  public static final String REQUEST_ID_HEADER = "x-request-id";
  private static final String SIGNED_CONTEXT_PREFIX = "agctx1";
  private static final int MIN_SIGNING_KEY_BYTES = 32;
  private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();
  private static final IAuthguardLogger SYSTEM_LOGGER = new SystemAuthguardLogger();
  private static final IAuthguardLogger NOOP_LOGGER = (_level, _event, _fields) -> {};
  private static final IAuthguardTelemetryObserver NOOP_OBSERVER = (_event, _fields) -> {};
  private static volatile IAuthguardLogger logger = SYSTEM_LOGGER;
  private static volatile IAuthguardTelemetryObserver telemetryObserver = NOOP_OBSERVER;

  private AuthguardUtils() {}

  /** Minimal logging facade that lets applications bridge Authguard events to their logger. */
  @FunctionalInterface
  public interface IAuthguardLogger {
    void log(LogLevel level, String event, Map<String, Object> fields);
  }

  /** Application bridge for OTel counters, histograms, and spans. */
  @FunctionalInterface
  public interface IAuthguardTelemetryObserver {
    void observe(String event, Map<String, Object> fields);
  }

  public enum LogLevel {
    DEBUG,
    WARN
  }

  /** Installs an application logger. Passing {@code null} disables adapter logging. */
  public static void configureLogger(IAuthguardLogger applicationLogger) {
    logger = applicationLogger == null ? NOOP_LOGGER : applicationLogger;
  }

  /** Restores the JDK {@link System.Logger} facade used by default. */
  public static void resetLogger() {
    logger = SYSTEM_LOGGER;
  }

  /** Installs an app-owned OTel bridge; the SDK never initializes a global exporter. */
  public static void configureTelemetryObserver(IAuthguardTelemetryObserver observer) {
    telemetryObserver = observer == null ? NOOP_OBSERVER : observer;
  }

  public static void logDebug(String event, Object... keyValues) {
    log(LogLevel.DEBUG, event, keyValues);
  }

  public static void logWarn(String event, Object... keyValues) {
    log(LogLevel.WARN, event, keyValues);
  }

  /** Returns a stable error category without serializing exception messages or secrets. */
  public static String errorCategory(Throwable error) {
    return error == null ? "unknown" : error.getClass().getSimpleName();
  }

  private static void log(LogLevel level, String event, Object... keyValues) {
    if (keyValues.length % 2 != 0) {
      throw new IllegalArgumentException("Authguard log fields must be key/value pairs");
    }
    Map<String, Object> fields = new LinkedHashMap<>();
    for (int index = 0; index < keyValues.length; index += 2) {
      fields.put(String.valueOf(keyValues[index]), safeLogValue(keyValues[index + 1]));
    }
    Map<String, Object> immutableFields = Map.copyOf(fields);
    try {
      telemetryObserver.observe(event, immutableFields);
    } catch (RuntimeException ignored) {
      // Telemetry cannot be allowed to break authorization enforcement.
    }
    logger.log(level, event, immutableFields);
  }

  private static Object safeLogValue(Object value) {
    if (value == null) {
      return "none";
    }
    if (!(value instanceof CharSequence text)) {
      return value;
    }
    StringBuilder safe = new StringBuilder(Math.min(text.length(), 128));
    for (int index = 0; index < text.length() && safe.length() < 128; index++) {
      char character = text.charAt(index);
      safe.append(Character.isISOControl(character) ? '_' : character);
    }
    return safe.toString();
  }

  private static final class SystemAuthguardLogger implements IAuthguardLogger {
    private static final System.Logger LOGGER =
        System.getLogger("com.authguard.adapter");

    @Override
    public void log(LogLevel level, String event, Map<String, Object> fields) {
      System.Logger.Level systemLevel =
          level == LogLevel.WARN ? System.Logger.Level.WARNING : System.Logger.Level.DEBUG;
      if (!LOGGER.isLoggable(systemLevel)) {
        return;
      }
      StringJoiner message = new StringJoiner(" ", "event=" + event, "");
      fields.forEach((key, value) -> message.add(key + "=" + Objects.toString(value)));
      LOGGER.log(systemLevel, message.toString());
    }
  }

  public static String encodeAccessContext(AccessContext accessContext) {
    validateAccessContext(accessContext, Instant.now().getEpochSecond());
    try {
      return Base64.getUrlEncoder()
          .withoutPadding()
          .encodeToString(OBJECT_MAPPER.writeValueAsBytes(accessContext));
    } catch (IOException error) {
      throw new IllegalArgumentException("cannot encode Authguard access context", error);
    }
  }

  public static AccessContext decodeAccessContext(String encoded) {
    long started = System.nanoTime();
    try {
      AccessContext accessContext = decodeAccessContextInternal(encoded);
      logDebug(
          "authguard.access_context.decode.succeeded",
          "principal_id",
          accessContext.principalId(),
          "action",
          accessContext.action(),
          "allow_count",
          accessContext.allowResourceUrns().size(),
          "deny_count",
          accessContext.denyResourceUrns().size(),
          "policy_revision",
          accessContext.policyRevision(),
          "duration_ms",
          elapsedMillis(started));
      return accessContext;
    } catch (IOException | IllegalArgumentException error) {
      logDebug(
          "authguard.access_context.decode.failed",
          "error_category",
          errorCategory(error),
          "duration_ms",
          elapsedMillis(started));
      throw new IllegalArgumentException("invalid Authguard access context", error);
    }
  }

  private static AccessContext decodeAccessContextInternal(String encoded) throws IOException {
    AccessContext accessContext =
        OBJECT_MAPPER.readValue(Base64.getUrlDecoder().decode(encoded), AccessContext.class);
    validateAccessContext(accessContext, Instant.now().getEpochSecond());
    return accessContext;
  }

  public static String signAccessContext(AccessContext accessContext, String signingKey) {
    return signEncodedAccessContext(encodeAccessContext(accessContext), signingKey);
  }

  public static String signEncodedAccessContext(String encoded, String signingKey) {
    byte[] key = validatedSigningKey(signingKey);
    String signingInput = SIGNED_CONTEXT_PREFIX + "." + encoded;
    return signingInput + "." + Base64.getUrlEncoder().withoutPadding().encodeToString(hmac(key, signingInput));
  }

  public static AccessContext verifySignedAccessContext(String signedContext, String signingKey) {
    long started = System.nanoTime();
    try {
      AccessContext context = verifySignedAccessContextInternal(signedContext, signingKey);
      logDebug(
          "authguard.access_context.verify.succeeded",
          "principal_id",
          context.principalId(),
          "action",
          context.action(),
          "allow_count",
          context.allowResourceUrns().size(),
          "deny_count",
          context.denyResourceUrns().size(),
          "duration_ms",
          elapsedMillis(started));
      return context;
    } catch (RuntimeException error) {
      logDebug(
          "authguard.access_context.verify.failed",
          "error_category",
          errorCategory(error),
          "duration_ms",
          elapsedMillis(started));
      throw error;
    }
  }

  private static AccessContext verifySignedAccessContextInternal(
      String signedContext, String signingKey) {
    byte[] key = validatedSigningKey(signingKey);
    String[] parts = signedContext.split("\\.", -1);
    if (parts.length != 3
        || !SIGNED_CONTEXT_PREFIX.equals(parts[0])
        || parts[1].isEmpty()
        || parts[2].isEmpty()) {
      throw new IllegalArgumentException("invalid signed Authguard access context format");
    }
    byte[] signature;
    try {
      signature = Base64.getUrlDecoder().decode(parts[2]);
    } catch (IllegalArgumentException error) {
      throw new IllegalArgumentException("invalid signed Authguard access context format", error);
    }
    String signingInput = parts[0] + "." + parts[1];
    if (!MessageDigest.isEqual(signature, hmac(key, signingInput))) {
      throw new IllegalArgumentException("invalid signed Authguard access context signature");
    }
    try {
      return decodeAccessContextInternal(parts[1]);
    } catch (IOException | IllegalArgumentException error) {
      throw new IllegalArgumentException("invalid Authguard access context", error);
    }
  }

  private static byte[] validatedSigningKey(String signingKey) {
    if (signingKey == null) {
      throw new IllegalArgumentException("access context signing key is required");
    }
    byte[] key = signingKey.getBytes(StandardCharsets.UTF_8);
    if (key.length < MIN_SIGNING_KEY_BYTES) {
      throw new IllegalArgumentException(
          "access context signing key must contain at least " + MIN_SIGNING_KEY_BYTES + " bytes");
    }
    return key;
  }

  private static byte[] hmac(byte[] key, String signingInput) {
    try {
      Mac mac = Mac.getInstance("HmacSHA256");
      mac.init(new SecretKeySpec(key, "HmacSHA256"));
      return mac.doFinal(signingInput.getBytes(StandardCharsets.US_ASCII));
    } catch (GeneralSecurityException error) {
      throw new IllegalStateException("HmacSHA256 is unavailable", error);
    }
  }

  public static void validateAccessContext(AccessContext accessContext, long nowEpochSeconds) {
    if (accessContext.version() != ACCESS_CONTEXT_VERSION) {
      throw new IllegalArgumentException(
          "unsupported access context version: " + accessContext.version());
    }
    if (accessContext.principalId() == null
        || accessContext.principalId().isEmpty()
        || accessContext.action() == null
        || accessContext.action().isEmpty()
        || accessContext.resourceUrn() == null
        || accessContext.resourceUrn().isEmpty()) {
      throw new IllegalArgumentException(
          "access context principal_id, action, and resource_urn are required");
    }
    if (accessContext.expiresAtEpochSeconds() <= accessContext.issuedAtEpochSeconds()) {
      throw new IllegalArgumentException("access context expiry must be later than issue time");
    }
    if (accessContext.issuedAtEpochSeconds() > nowEpochSeconds + 30) {
      throw new IllegalArgumentException("access context issue time is in the future");
    }
    if (accessContext.expiresAtEpochSeconds() <= nowEpochSeconds) {
      throw new IllegalArgumentException("access context has expired");
    }
  }

  public static UrnPattern parseUrnPattern(String raw) {
    String[] parts = raw.split(":", 7);
    if (parts.length != 7 || !"urn".equals(parts[0]) || !"iam".equals(parts[1]) || parts[6].contains(":")) {
      throw new IllegalArgumentException("invalid authguard urn: " + raw);
    }
    for (int i = 2; i < 6; i++) {
      String segment = parts[i];
      if (segment.isEmpty() || (segment.contains("*") && !"*".equals(segment))) {
        throw new IllegalArgumentException("invalid authguard urn segment: " + raw);
      }
    }

    List<String> path = Arrays.asList(parts[6].split("/"));
    if (path.isEmpty() || path.stream().anyMatch(String::isEmpty)) {
      throw new IllegalArgumentException("empty resource path segment: " + raw);
    }
    for (int i = 0; i < path.size(); i++) {
      String segment = path.get(i);
      if ("**".equals(segment) && i != path.size() - 1) {
        throw new IllegalArgumentException("** is only allowed as the final path segment");
      }
      if (segment.contains("*") && !"*".equals(segment) && !"**".equals(segment)) {
        throw new IllegalArgumentException("partial wildcard is not supported: " + segment);
      }
    }
    return new UrnPattern(parts[2], parts[3], parts[4], parts[5], path);
  }

  public static SqlScope compileScope(ResourceSqlMapping mapping, List<String> allow, List<String> deny) {
    long started = System.nanoTime();
    logDebug(
        "authguard.sql_scope.compile.started",
        "allow_count",
        allow.size(),
        "deny_count",
        deny.size());
    try {
      SqlScope scope = compileScopeInternal(mapping, allow, deny);
      logDebug(
          "authguard.sql_scope.compile.succeeded",
          "allow_count",
          allow.size(),
          "deny_count",
          deny.size(),
          "scope_kind",
          scopeKind(scope),
          "parameter_count",
          scope.args().size(),
          "duration_ms",
          elapsedMillis(started));
      return scope;
    } catch (RuntimeException error) {
      logDebug(
          "authguard.sql_scope.compile.failed",
          "allow_count",
          allow.size(),
          "deny_count",
          deny.size(),
          "error_category",
          errorCategory(error),
          "duration_ms",
          elapsedMillis(started));
      throw error;
    }
  }

  private static SqlScope compileScopeInternal(
      ResourceSqlMapping mapping, List<String> allow, List<String> deny) {
    List<SqlScope> allowScopes = new ArrayList<>();
    for (String raw : allow) {
      SqlScope scope = compilePattern(mapping, parseUrnPattern(raw));
      if (scope != null) {
        allowScopes.add(scope);
      }
    }
    if (allowScopes.isEmpty()) {
      return SqlScope.denyAll();
    }

    SqlScope scope = orScopes(allowScopes);
    for (String raw : deny) {
      SqlScope denyScope = compilePattern(mapping, parseUrnPattern(raw));
      if (denyScope == null) {
        continue;
      }
      if ("1=1".equals(denyScope.where())) {
        return SqlScope.denyAll();
      }
      List<String> args = new ArrayList<>(scope.args());
      args.addAll(denyScope.args());
      scope = new SqlScope("(" + scope.where() + ") AND NOT (" + denyScope.where() + ")", args);
    }
    return scope;
  }

  public static SqlScope currentScope(ResourceSqlMapping mapping) {
    AccessGrantSet grants = AuthguardAccess.ContextHolder.require();
    return mapping.compile(grants.allowResourceUrns(), grants.denyResourceUrns());
  }

  public static SqlScope currentScopeForAction(String expectedAction, ResourceSqlMapping mapping) {
    return scopeForAction(AuthguardAccess.ContextHolder.requireAccess(), expectedAction, mapping);
  }

  public static SqlScope scopeForAction(
      RequestAccess requestAccess, String expectedAction, ResourceSqlMapping mapping) {
    if (!expectedAction.equals(requestAccess.action())) {
      logDebug(
          "authguard.sql_scope.action_mismatch",
          "principal_id",
          requestAccess.principalId(),
          "expected_action",
          expectedAction,
          "actual_action",
          requestAccess.action());
      throw new SecurityException(
          "authguard action mismatch: expected `"
              + expectedAction
              + "`, got `"
              + requestAccess.action()
              + "`");
    }
    return mapping.compile(
        requestAccess.grants().allowResourceUrns(),
        requestAccess.grants().denyResourceUrns());
  }

  private static String scopeKind(SqlScope scope) {
    if ("0=1".equals(scope.where())) {
      return "deny_all";
    }
    if ("1=1".equals(scope.where())) {
      return "allow_all";
    }
    return "filtered";
  }

  private static long elapsedMillis(long startedNanos) {
    return (System.nanoTime() - startedNanos) / 1_000_000;
  }

  private static SqlScope compilePattern(ResourceSqlMapping mapping, UrnPattern pattern) {
    List<String> clauses = new ArrayList<>();
    List<String> args = new ArrayList<>();
    if (!compileSegment(mapping.partition(), pattern.partition(), clauses, args)
        || !compileSegment(mapping.service(), pattern.service(), clauses, args)
        || !compileSegment(mapping.region(), pattern.region(), clauses, args)
        || !compileSegment(mapping.tenant(), pattern.tenant(), clauses, args)
        || !compilePath(mapping.path(), pattern.path(), clauses, args)) {
      return null;
    }
    return scopeFrom(clauses, args);
  }

  private static boolean compilePath(
      List<PathMap> mappingPath, List<String> pattern, List<String> clauses, List<String> args) {
    int pidx = 0;
    for (PathMap mapping : mappingPath) {
      if (pidx < pattern.size() && "**".equals(pattern.get(pidx))) {
        return true;
      }
      switch (mapping.kind()) {
        case LITERAL -> {
          if (pidx >= pattern.size()) {
            return false;
          }
          String segment = pattern.get(pidx);
          if (!"*".equals(segment) && !mapping.value().equals(segment)) {
            return false;
          }
          pidx++;
        }
        case COLUMN -> {
          if (pidx >= pattern.size()) {
            return false;
          }
          String segment = pattern.get(pidx);
          if (!"*".equals(segment)) {
            clauses.add(mapping.value() + " = ?");
            args.add(segment);
          }
          pidx++;
        }
        case REMAINDER_COLUMN -> {
          compileRemainder(mapping.value(), pattern.subList(pidx, pattern.size()), clauses, args);
          pidx = pattern.size();
        }
      }
    }
    return pidx == pattern.size() || (pidx + 1 == pattern.size() && "**".equals(pattern.get(pidx)));
  }

  private static boolean compileSegment(
      SegmentMap mapping, String pattern, List<String> clauses, List<String> args) {
    if ("*".equals(pattern)) {
      return true;
    }
    if (mapping.kind() == SegmentMap.SegmentKind.CONSTANT) {
      return mapping.value().equals(pattern);
    }
    clauses.add(mapping.value() + " = ?");
    args.add(pattern);
    return true;
  }

  private static void compileRemainder(
      String column, List<String> remaining, List<String> clauses, List<String> args) {
    if (remaining.isEmpty() || remaining.equals(List.of("**"))) {
      return;
    }
    if (remaining.contains("*")) {
      throw new UnsupportedOperationException("wildcard inside a remainder column is not SQL-pushdown safe");
    }
    if ("**".equals(remaining.get(remaining.size() - 1))) {
      String prefix = String.join("/", remaining.subList(0, remaining.size() - 1));
      if (!prefix.isEmpty()) {
        clauses.add("(" + column + " = ? OR " + column + " LIKE ?)");
        args.add(prefix);
        args.add(prefix + "/%");
      }
      return;
    }
    clauses.add(column + " = ?");
    args.add(String.join("/", remaining));
  }

  private static SqlScope scopeFrom(List<String> clauses, List<String> args) {
    if (clauses.isEmpty()) {
      return SqlScope.allowAll();
    }
    return new SqlScope(String.join(" AND ", clauses), args);
  }

  private static SqlScope orScopes(List<SqlScope> scopes) {
    if (scopes.size() == 1) {
      return scopes.get(0);
    }
    if (scopes.stream().anyMatch(scope -> "1=1".equals(scope.where()))) {
      return SqlScope.allowAll();
    }
    StringJoiner joiner = new StringJoiner(" OR ");
    List<String> args = new ArrayList<>();
    for (SqlScope scope : scopes) {
      joiner.add("(" + scope.where() + ")");
      args.addAll(scope.args());
    }
    return new SqlScope(joiner.toString(), args);
  }

}
