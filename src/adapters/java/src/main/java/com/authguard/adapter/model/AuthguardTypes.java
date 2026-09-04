package com.authguard.adapter.model;

import com.authguard.adapter.util.AuthguardUtils;
import com.fasterxml.jackson.annotation.JsonAlias;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.time.Duration;
import java.time.Instant;
import java.util.List;

public final class AuthguardTypes {
  public static final int ACCESS_CONTEXT_VERSION = 3;

  private AuthguardTypes() {}

  public record SqlScope(String where, List<String> args) {
    public SqlScope {
      args = List.copyOf(args);
    }

    public static SqlScope denyAll() {
      return new SqlScope("0=1", List.of());
    }

    public static SqlScope allowAll() {
      return new SqlScope("1=1", List.of());
    }
  }

  public record SegmentMap(SegmentKind kind, String value) {
    public enum SegmentKind {
      CONSTANT,
      COLUMN
    }

    public static SegmentMap constant(String value) {
      return new SegmentMap(SegmentKind.CONSTANT, value);
    }

    public static SegmentMap column(String name) {
      return new SegmentMap(SegmentKind.COLUMN, name);
    }
  }

  public record PathMap(PathKind kind, String value) {
    public enum PathKind {
      LITERAL,
      COLUMN,
      REMAINDER_COLUMN
    }

    public static PathMap literal(String value) {
      return new PathMap(PathKind.LITERAL, value);
    }

    public static PathMap column(String name) {
      return new PathMap(PathKind.COLUMN, name);
    }

    public static PathMap remainderColumn(String name) {
      return new PathMap(PathKind.REMAINDER_COLUMN, name);
    }
  }

  public record UrnPattern(
      String partition, String service, String region, String tenant, List<String> path) {
    public UrnPattern {
      path = List.copyOf(path);
    }
  }

  public record ResourceSqlMapping(
      SegmentMap partition, SegmentMap service, SegmentMap region, SegmentMap tenant, List<PathMap> path) {
    public ResourceSqlMapping {
      path = List.copyOf(path);
    }

    public SqlScope compile(List<String> allow, List<String> deny) {
      return AuthguardUtils.compileScope(this, allow, deny);
    }
  }

  public record AccessGrantSet(List<String> allowResourceUrns, List<String> denyResourceUrns) {
    public AccessGrantSet {
      allowResourceUrns = List.copyOf(allowResourceUrns);
      denyResourceUrns = List.copyOf(denyResourceUrns);
    }

    public static AccessGrantSet empty() {
      return new AccessGrantSet(List.of(), List.of());
    }
  }

  public record RequestAccess(
      String principalId, String action, String resourceUrn, AccessGrantSet grants) {
    public static RequestAccess fromGrants(AccessGrantSet grants) {
      return new RequestAccess("", "", "", grants);
    }
  }

  public record AccessContext(
      @JsonProperty("version") int version,
      @JsonProperty("principal_id") @JsonAlias("subject_id") String principalId,
      @JsonProperty("action") String action,
      @JsonProperty("resource_urn") String resourceUrn,
      @JsonProperty("allow_resource_urns") List<String> allowResourceUrns,
      @JsonProperty("deny_resource_urns") List<String> denyResourceUrns,
      @JsonProperty("policy_revision") @JsonAlias("policy_version") long policyRevision,
      @JsonProperty("issued_at_epoch_seconds") long issuedAtEpochSeconds,
      @JsonProperty("expires_at_epoch_seconds") long expiresAtEpochSeconds) {
    public AccessContext {
      allowResourceUrns = List.copyOf(allowResourceUrns);
      denyResourceUrns = List.copyOf(denyResourceUrns);
    }

    public static AccessContext active(
        String principalId,
        String action,
        String resourceUrn,
        List<String> allowResourceUrns,
        List<String> denyResourceUrns) {
      long now = Instant.now().getEpochSecond();
      return new AccessContext(
          ACCESS_CONTEXT_VERSION,
          principalId,
          action,
          resourceUrn,
          allowResourceUrns,
          denyResourceUrns,
          1,
          now,
          now + Duration.ofSeconds(30).toSeconds());
    }

    public AccessGrantSet grantSet() {
      return new AccessGrantSet(allowResourceUrns, denyResourceUrns);
    }

    public RequestAccess requestAccess() {
      return new RequestAccess(principalId, action, resourceUrn, grantSet());
    }
  }
}
