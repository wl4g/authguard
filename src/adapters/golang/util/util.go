package util

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"reflect"
	"strings"
	"sync/atomic"
	"time"

	"authguard/adapters/golang/model"
)

const AccessContextHeader = "x-authguard-context"
const ScopeTokenHeader = "x-authguard-scope-token"
const RequestIDHeader = "x-request-id"
const signedContextPrefix = "agctx1"
const minSigningKeyBytes = 32

var configuredLogger atomic.Pointer[slog.Logger]

// ConfigureLogger installs an application-owned structured logger. Passing nil disables logging.
func ConfigureLogger(logger *slog.Logger) {
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	configuredLogger.Store(logger)
}

// ResetLogger restores delegation to slog.Default.
func ResetLogger() {
	configuredLogger.Store(nil)
}

// LogDebug emits a structured adapter event without serializing request credentials.
func LogDebug(ctx context.Context, event string, args ...any) {
	adapterLogger().DebugContext(ctx, event, append([]any{"event", event}, args...)...)
}

// LogWarn emits a structured infrastructure-failure event.
func LogWarn(ctx context.Context, event string, args ...any) {
	adapterLogger().WarnContext(ctx, event, append([]any{"event", event}, args...)...)
}

// ErrorCategory returns a stable type name and never includes an error message.
func ErrorCategory(err error) string {
	if err == nil {
		return "unknown"
	}
	for errors.Unwrap(err) != nil {
		err = errors.Unwrap(err)
	}
	errorType := reflect.TypeOf(err)
	for errorType.Kind() == reflect.Pointer {
		errorType = errorType.Elem()
	}
	if errorType.Name() == "" {
		return "error"
	}
	return errorType.Name()
}

// SafeLogString bounds identifiers and removes control characters before logging.
func SafeLogString(value string) string {
	const maxRunes = 128
	var result strings.Builder
	for _, character := range value {
		if result.Len() >= maxRunes {
			break
		}
		if character < 0x20 || character == 0x7f {
			result.WriteByte('_')
		} else {
			result.WriteRune(character)
		}
	}
	return result.String()
}

func adapterLogger() *slog.Logger {
	if logger := configuredLogger.Load(); logger != nil {
		return logger
	}
	return slog.Default()
}

func EncodeAccessContext(accessContext model.AccessContext) (string, error) {
	if err := ValidateAccessContext(accessContext, uint64(time.Now().Unix())); err != nil {
		return "", err
	}
	payload, err := json.Marshal(accessContext)
	if err != nil {
		return "", fmt.Errorf("encode access context: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(payload), nil
}

func DecodeAccessContext(encoded string) (model.AccessContext, error) {
	started := time.Now()
	accessContext, err := decodeAccessContext(encoded)
	if err != nil {
		LogDebug(context.Background(), "authguard.access_context.decode.failed",
			"error_category", ErrorCategory(err), "duration_ms", time.Since(started).Milliseconds())
		return model.AccessContext{}, err
	}
	LogDebug(context.Background(), "authguard.access_context.decode.succeeded",
		"principal_id", SafeLogString(accessContext.PrincipalID),
		"action", SafeLogString(accessContext.Action),
		"allow_count", len(accessContext.AllowResourceURNs),
		"deny_count", len(accessContext.DenyResourceURNs),
		"policy_revision", accessContext.PolicyRevision,
		"duration_ms", time.Since(started).Milliseconds())
	return accessContext, nil
}

func decodeAccessContext(encoded string) (model.AccessContext, error) {
	payload, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return model.AccessContext{}, fmt.Errorf("decode access context base64url: %w", err)
	}
	var accessContext model.AccessContext
	if err := json.Unmarshal(payload, &accessContext); err != nil {
		return model.AccessContext{}, fmt.Errorf("decode access context json: %w", err)
	}
	if err := ValidateAccessContext(accessContext, uint64(time.Now().Unix())); err != nil {
		return model.AccessContext{}, err
	}
	return accessContext, nil
}

func SignAccessContext(accessContext model.AccessContext, signingKey string) (string, error) {
	encoded, err := EncodeAccessContext(accessContext)
	if err != nil {
		return "", err
	}
	return SignEncodedAccessContext(encoded, signingKey)
}

func SignEncodedAccessContext(encoded string, signingKey string) (string, error) {
	if len([]byte(signingKey)) < minSigningKeyBytes {
		return "", fmt.Errorf("access context signing key must contain at least %d bytes", minSigningKeyBytes)
	}
	signingInput := signedContextPrefix + "." + encoded
	mac := hmac.New(sha256.New, []byte(signingKey))
	_, _ = mac.Write([]byte(signingInput))
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil)), nil
}

func VerifySignedAccessContext(signedContext string, signingKey string) (model.AccessContext, error) {
	started := time.Now()
	contextValue, err := verifySignedAccessContext(signedContext, signingKey)
	if err != nil {
		LogDebug(context.Background(), "authguard.access_context.verify.failed",
			"error_category", ErrorCategory(err), "duration_ms", time.Since(started).Milliseconds())
		return model.AccessContext{}, err
	}
	LogDebug(context.Background(), "authguard.access_context.verify.succeeded",
		"principal_id", SafeLogString(contextValue.PrincipalID),
		"action", SafeLogString(contextValue.Action),
		"allow_count", len(contextValue.AllowResourceURNs),
		"deny_count", len(contextValue.DenyResourceURNs),
		"duration_ms", time.Since(started).Milliseconds())
	return contextValue, nil
}

func verifySignedAccessContext(signedContext string, signingKey string) (model.AccessContext, error) {
	if len([]byte(signingKey)) < minSigningKeyBytes {
		return model.AccessContext{}, fmt.Errorf("access context signing key must contain at least %d bytes", minSigningKeyBytes)
	}
	parts := strings.Split(signedContext, ".")
	if len(parts) != 3 || parts[0] != signedContextPrefix || parts[1] == "" || parts[2] == "" {
		return model.AccessContext{}, errors.New("invalid signed access context format")
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return model.AccessContext{}, errors.New("invalid signed access context format")
	}
	signingInput := parts[0] + "." + parts[1]
	mac := hmac.New(sha256.New, []byte(signingKey))
	_, _ = mac.Write([]byte(signingInput))
	if !hmac.Equal(signature, mac.Sum(nil)) {
		return model.AccessContext{}, errors.New("invalid signed access context signature")
	}
	return decodeAccessContext(parts[1])
}

func ValidateAccessContext(accessContext model.AccessContext, now uint64) error {
	if accessContext.Version != model.AccessContextVersion {
		return fmt.Errorf("unsupported access context version: %d", accessContext.Version)
	}
	if accessContext.ExpiresAtEpochSec <= accessContext.IssuedAtEpochSec {
		return fmt.Errorf("access context expiry must be later than issue time")
	}
	if accessContext.IssuedAtEpochSec > now+30 {
		return fmt.Errorf("access context issue time is in the future")
	}
	if accessContext.ExpiresAtEpochSec <= now {
		return fmt.Errorf("access context has expired")
	}
	return nil
}

func ParseURNPattern(raw string) (model.URNPattern, error) {
	parts := strings.SplitN(raw, ":", 7)
	if len(parts) != 7 || parts[0] != "urn" || parts[1] != "iam" || parts[6] == "" || strings.Contains(parts[6], ":") {
		return model.URNPattern{}, fmt.Errorf("invalid authguard urn: %s", raw)
	}
	for _, segment := range parts[2:6] {
		if segment == "" || strings.Contains(segment, "*") && segment != "*" {
			return model.URNPattern{}, fmt.Errorf("invalid authguard urn segment in %s", raw)
		}
	}
	path := strings.Split(parts[6], "/")
	for i, seg := range path {
		if seg == "" {
			return model.URNPattern{}, fmt.Errorf("empty resource path segment in %s", raw)
		}
		if seg == "**" && i != len(path)-1 {
			return model.URNPattern{}, fmt.Errorf("** is only allowed as the final path segment")
		}
		if strings.Contains(seg, "*") && seg != "*" && seg != "**" {
			return model.URNPattern{}, fmt.Errorf("partial wildcard is not supported: %s", seg)
		}
	}
	return model.URNPattern{Partition: parts[2], Service: parts[3], Region: parts[4], Tenant: parts[5], Path: path}, nil
}

func CompileScope(mapping model.ResourceSQLMapping, allow []string, deny []string) (model.SqlScope, error) {
	started := time.Now()
	LogDebug(context.Background(), "authguard.sql_scope.compile.started",
		"allow_count", len(allow), "deny_count", len(deny))
	scope, err := compileScope(mapping, allow, deny)
	if err != nil {
		LogDebug(context.Background(), "authguard.sql_scope.compile.failed",
			"allow_count", len(allow), "deny_count", len(deny),
			"error_category", ErrorCategory(err), "duration_ms", time.Since(started).Milliseconds())
		return model.SqlScope{}, err
	}
	LogDebug(context.Background(), "authguard.sql_scope.compile.succeeded",
		"allow_count", len(allow), "deny_count", len(deny),
		"scope_kind", scopeKind(scope), "parameter_count", len(scope.Args),
		"duration_ms", time.Since(started).Milliseconds())
	return scope, nil
}

func compileScope(mapping model.ResourceSQLMapping, allow []string, deny []string) (model.SqlScope, error) {
	allowScopes := make([]model.SqlScope, 0, len(allow))
	for _, raw := range allow {
		pattern, err := ParseURNPattern(raw)
		if err != nil {
			return model.SqlScope{}, err
		}
		scope, ok, err := compilePattern(mapping, pattern)
		if err != nil {
			return model.SqlScope{}, err
		}
		if ok {
			allowScopes = append(allowScopes, scope)
		}
	}
	if len(allowScopes) == 0 {
		return model.SqlScope{Where: "0=1", Args: []any{}}, nil
	}

	scope := orScopes(allowScopes)
	for _, raw := range deny {
		pattern, err := ParseURNPattern(raw)
		if err != nil {
			return model.SqlScope{}, err
		}
		denyScope, ok, err := compilePattern(mapping, pattern)
		if err != nil {
			return model.SqlScope{}, err
		}
		if !ok {
			continue
		}
		if denyScope.Where == "1=1" {
			return model.SqlScope{Where: "0=1", Args: []any{}}, nil
		}
		scope.Where = "(" + scope.Where + ") AND NOT (" + denyScope.Where + ")"
		scope.Args = append(scope.Args, denyScope.Args...)
	}
	return scope, nil
}

func scopeKind(scope model.SqlScope) string {
	switch scope.Where {
	case "0=1":
		return "deny_all"
	case "1=1":
		return "allow_all"
	default:
		return "filtered"
	}
}

func compilePattern(mapping model.ResourceSQLMapping, pattern model.URNPattern) (model.SqlScope, bool, error) {
	clauses := make([]string, 0, len(mapping.Path)+4)
	args := make([]any, 0, len(mapping.Path)+4)
	if !compileSegment(mapping.Partition, pattern.Partition, &clauses, &args) ||
		!compileSegment(mapping.Service, pattern.Service, &clauses, &args) ||
		!compileSegment(mapping.Region, pattern.Region, &clauses, &args) ||
		!compileSegment(mapping.Tenant, pattern.Tenant, &clauses, &args) {
		return model.SqlScope{}, false, nil
	}
	ok, err := compilePath(mapping.Path, pattern.Path, &clauses, &args)
	if err != nil || !ok {
		return model.SqlScope{}, false, err
	}
	return scopeFrom(clauses, args), true, nil
}

func compileSegment(mapping model.SegmentMap, pattern string, clauses *[]string, args *[]any) bool {
	if pattern == "*" {
		return true
	}
	if mapping.Kind == model.SegmentConstant {
		return mapping.Value == pattern
	}
	*clauses = append(*clauses, mapping.Value+" = ?")
	*args = append(*args, pattern)
	return true
}

func compilePath(mappingPath []model.PathMap, pattern []string, clauses *[]string, args *[]any) (bool, error) {
	pidx := 0
	for _, mapping := range mappingPath {
		if pidx < len(pattern) && pattern[pidx] == "**" {
			return true, nil
		}
		switch mapping.Kind {
		case model.PathLiteral:
			if pidx >= len(pattern) {
				return false, nil
			}
			segment := pattern[pidx]
			if segment != "*" && segment != mapping.Value {
				return false, nil
			}
			pidx++
		case model.PathColumn:
			if pidx >= len(pattern) {
				return false, nil
			}
			segment := pattern[pidx]
			if segment != "*" {
				*clauses = append(*clauses, mapping.Value+" = ?")
				*args = append(*args, segment)
			}
			pidx++
		case model.PathRemainderColumn:
			if err := compileRemainder(mapping.Value, pattern[pidx:], clauses, args); err != nil {
				return false, err
			}
			pidx = len(pattern)
		}
	}
	return pidx == len(pattern) || (pidx+1 == len(pattern) && pattern[pidx] == "**"), nil
}

func compileRemainder(column string, remaining []string, clauses *[]string, args *[]any) error {
	if len(remaining) == 0 || len(remaining) == 1 && remaining[0] == "**" {
		return nil
	}
	for _, segment := range remaining {
		if segment == "*" {
			return fmt.Errorf("wildcard inside a remainder column is not SQL-pushdown safe")
		}
	}
	if remaining[len(remaining)-1] == "**" {
		prefix := strings.Join(remaining[:len(remaining)-1], "/")
		if prefix != "" {
			*clauses = append(*clauses, "("+column+" = ? OR "+column+" LIKE ?)")
			*args = append(*args, prefix, prefix+"/%")
		}
		return nil
	}
	*clauses = append(*clauses, column+" = ?")
	*args = append(*args, strings.Join(remaining, "/"))
	return nil
}

func scopeFrom(clauses []string, args []any) model.SqlScope {
	if len(clauses) == 0 {
		return model.SqlScope{Where: "1=1", Args: args}
	}
	return model.SqlScope{Where: strings.Join(clauses, " AND "), Args: args}
}

func orScopes(scopes []model.SqlScope) model.SqlScope {
	if len(scopes) == 1 {
		return scopes[0]
	}
	for _, scope := range scopes {
		if scope.Where == "1=1" {
			return model.SqlScope{Where: "1=1"}
		}
	}
	parts := make([]string, 0, len(scopes))
	args := make([]any, 0)
	for _, scope := range scopes {
		parts = append(parts, "("+scope.Where+")")
		args = append(args, scope.Args...)
	}
	return model.SqlScope{Where: strings.Join(parts, " OR "), Args: args}
}
