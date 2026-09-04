package access

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"authguard/adapters/golang/model"
	"authguard/adapters/golang/util"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

const resolveScopeMethod = "/authguard.access.v1.AccessContextService/ResolveScope"

const (
	GRPCTargetEnv           = "AUTHGUARD_GRPC_TARGET"
	GRPCTLSEnv              = "AUTHGUARD_GRPC_TLS"
	AccessContextHMACKeyEnv = "AUTHGUARD_ACCESS_CONTEXT_HMAC_KEY"
)

var (
	ErrAccessContextUnavailable = errors.New("authguard access context is not available")
	ErrScopeResolverUnavailable = errors.New("no resolver is configured for the Authguard scope token")
)

type ActionMismatchError struct {
	Expected string
	Actual   string
}

func (e ActionMismatchError) Error() string {
	return "authguard action mismatch: expected `" + e.Expected + "`, got `" + e.Actual + "`"
}

type HeaderReader interface {
	Header(name string) string
}

type IAccessContextResolver interface {
	Resolve(ctx context.Context, headers HeaderReader) (*model.RequestAccess, error)
}

type ScopeTokenClient interface {
	ResolveScope(ctx context.Context, token string) (string, error)
}

type GRPCScopeTokenClient struct {
	connection *grpc.ClientConn
}

func NewGRPCScopeTokenClient(target string, options ...grpc.DialOption) (*GRPCScopeTokenClient, error) {
	connection, err := grpc.NewClient(target, options...)
	if err != nil {
		return nil, fmt.Errorf("create Authguard scope resolver client: %w", err)
	}
	return &GRPCScopeTokenClient{connection: connection}, nil
}

func NewGRPCScopeTokenClientFromEnv() (*GRPCScopeTokenClient, error) {
	target := strings.TrimSpace(os.Getenv(GRPCTargetEnv))
	if target == "" {
		return nil, fmt.Errorf("%s is required", GRPCTargetEnv)
	}
	tlsEnabled, err := parseBool(defaultString(os.Getenv(GRPCTLSEnv), "false"))
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", GRPCTLSEnv, err)
	}
	transportCredentials := credentials.TransportCredentials(insecure.NewCredentials())
	if tlsEnabled {
		transportCredentials = credentials.NewTLS(&tls.Config{MinVersion: tls.VersionTLS12})
	}
	util.LogDebug(context.Background(), "authguard.scope_token.grpc.configured",
		"resolver_mode", "grpc", "tls", tlsEnabled)
	return NewGRPCScopeTokenClient(
		target,
		grpc.WithTransportCredentials(transportCredentials),
	)
}

func (c *GRPCScopeTokenClient) ResolveScope(ctx context.Context, token string) (string, error) {
	started := time.Now()
	util.LogDebug(ctx, "authguard.scope_token.grpc.started", "resolver_mode", "grpc")
	response := new(wrapperspb.StringValue)
	if err := c.connection.Invoke(ctx, resolveScopeMethod, wrapperspb.String(token), response); err != nil {
		util.LogWarn(ctx, "authguard.scope_token.grpc.failed",
			"resolver_mode", "grpc", "error_category", util.ErrorCategory(err),
			"duration_ms", time.Since(started).Milliseconds())
		return "", fmt.Errorf("resolve Authguard scope token: %w", err)
	}
	util.LogDebug(ctx, "authguard.scope_token.grpc.succeeded",
		"resolver_mode", "grpc", "duration_ms", time.Since(started).Milliseconds())
	return response.Value, nil
}

func (c *GRPCScopeTokenClient) Close() error {
	return c.connection.Close()
}

// HeaderAccessContextResolver verifies and decodes the context injected by Envoy.
type HeaderAccessContextResolver struct {
	signingKey string
}

func NewHeaderAccessContextResolver(signingKey string) (HeaderAccessContextResolver, error) {
	if _, err := util.SignEncodedAccessContext("probe", signingKey); err != nil {
		return HeaderAccessContextResolver{}, err
	}
	return HeaderAccessContextResolver{signingKey: signingKey}, nil
}

func NewHeaderAccessContextResolverFromEnv() (HeaderAccessContextResolver, error) {
	signingKey := os.Getenv(AccessContextHMACKeyEnv)
	if signingKey == "" {
		return HeaderAccessContextResolver{}, fmt.Errorf("%s is required", AccessContextHMACKeyEnv)
	}
	return NewHeaderAccessContextResolver(signingKey)
}

func (r HeaderAccessContextResolver) Resolve(
	_ context.Context,
	headers HeaderReader,
) (*model.RequestAccess, error) {
	encoded := headers.Header(util.AccessContextHeader)
	if encoded == "" {
		return nil, nil
	}
	signingKey := r.signingKey
	if signingKey == "" {
		signingKey = os.Getenv(AccessContextHMACKeyEnv)
	}
	if signingKey == "" {
		return nil, fmt.Errorf("%s is required", AccessContextHMACKeyEnv)
	}
	accessContext, err := util.VerifySignedAccessContext(encoded, signingKey)
	if err != nil {
		return nil, err
	}
	requestAccess := accessContext.RequestAccess()
	return &requestAccess, nil
}

// GRPCAccessContextResolver exchanges a request-scoped opaque token for the
// complete access context through Authguard's gRPC API.
type GRPCAccessContextResolver struct {
	client ScopeTokenClient
}

func NewGRPCAccessContextResolver(client ScopeTokenClient) GRPCAccessContextResolver {
	return GRPCAccessContextResolver{client: client}
}

func NewGRPCAccessContextResolverFromEnv() (GRPCAccessContextResolver, error) {
	client, err := NewGRPCScopeTokenClientFromEnv()
	if err != nil {
		return GRPCAccessContextResolver{}, err
	}
	return NewGRPCAccessContextResolver(client), nil
}

func (r GRPCAccessContextResolver) Close() error {
	if closer, ok := r.client.(interface{ Close() error }); ok {
		return closer.Close()
	}
	return nil
}

func (r GRPCAccessContextResolver) Resolve(
	ctx context.Context,
	headers HeaderReader,
) (*model.RequestAccess, error) {
	token := headers.Header(util.ScopeTokenHeader)
	if token == "" {
		return nil, nil
	}
	if r.client == nil {
		return nil, ErrScopeResolverUnavailable
	}
	encoded, err := r.client.ResolveScope(ctx, token)
	if err != nil {
		return nil, err
	}
	accessContext, err := util.DecodeAccessContext(encoded)
	if err != nil {
		return nil, err
	}
	requestAccess := accessContext.RequestAccess()
	return &requestAccess, nil
}

type contextKey struct{}

type contextValue struct {
	access  model.RequestAccess
	present bool
}

func WithGrantSet(ctx context.Context, grants model.AccessGrantSet) context.Context {
	return WithRequestAccess(ctx, model.RequestAccess{Grants: grants})
}

func WithRequestAccess(ctx context.Context, requestAccess model.RequestAccess) context.Context {
	util.LogDebug(ctx, "authguard.access_context.bound",
		"principal_id", util.SafeLogString(requestAccess.PrincipalID),
		"action", util.SafeLogString(requestAccess.Action),
		"allow_count", len(requestAccess.Grants.AllowResourceURNs),
		"deny_count", len(requestAccess.Grants.DenyResourceURNs))
	return context.WithValue(ctx, contextKey{}, contextValue{access: requestAccess, present: true})
}

func WithoutGrantSet(ctx context.Context) context.Context {
	if current, ok := RequestAccess(ctx); ok {
		util.LogDebug(ctx, "authguard.access_context.cleared",
			"principal_id", util.SafeLogString(current.PrincipalID),
			"action", util.SafeLogString(current.Action))
	}
	return context.WithValue(ctx, contextKey{}, contextValue{})
}

func GrantSet(ctx context.Context) (model.AccessGrantSet, bool) {
	value, ok := ctx.Value(contextKey{}).(contextValue)
	if !ok || !value.present {
		return model.AccessGrantSet{}, false
	}
	return value.access.Grants, true
}

func RequestAccess(ctx context.Context) (model.RequestAccess, bool) {
	value, ok := ctx.Value(contextKey{}).(contextValue)
	if !ok || !value.present {
		return model.RequestAccess{}, false
	}
	return value.access, true
}

func RequireGrantSet(ctx context.Context) (model.AccessGrantSet, error) {
	grants, ok := GrantSet(ctx)
	if !ok {
		util.LogDebug(ctx, "authguard.access_context.required_missing")
		return model.AccessGrantSet{}, ErrAccessContextUnavailable
	}
	return grants, nil
}

func RequireRequestAccess(ctx context.Context) (model.RequestAccess, error) {
	requestAccess, ok := RequestAccess(ctx)
	if !ok {
		util.LogDebug(ctx, "authguard.access_context.required_missing")
		return model.RequestAccess{}, ErrAccessContextUnavailable
	}
	return requestAccess, nil
}

func CurrentScope(ctx context.Context, mapping model.ResourceSQLMapping) (model.SqlScope, error) {
	grants, err := RequireGrantSet(ctx)
	if err != nil {
		return model.SqlScope{}, err
	}
	return util.CompileScope(mapping, grants.AllowResourceURNs, grants.DenyResourceURNs)
}

func CurrentScopeForAction(
	ctx context.Context,
	expectedAction string,
	mapping model.ResourceSQLMapping,
) (model.SqlScope, error) {
	requestAccess, err := RequireRequestAccess(ctx)
	if err != nil {
		return model.SqlScope{}, err
	}
	return ScopeForAction(requestAccess, expectedAction, mapping)
}

func ScopeForAction(
	requestAccess model.RequestAccess,
	expectedAction string,
	mapping model.ResourceSQLMapping,
) (model.SqlScope, error) {
	if requestAccess.Action != expectedAction {
		util.LogDebug(context.Background(), "authguard.sql_scope.action_mismatch",
			"principal_id", util.SafeLogString(requestAccess.PrincipalID),
			"expected_action", util.SafeLogString(expectedAction),
			"actual_action", util.SafeLogString(requestAccess.Action))
		return model.SqlScope{}, ActionMismatchError{
			Expected: expectedAction,
			Actual:   requestAccess.Action,
		}
	}
	return util.CompileScope(
		mapping,
		requestAccess.Grants.AllowResourceURNs,
		requestAccess.Grants.DenyResourceURNs,
	)
}

func parseBool(value string) (bool, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "1", "true", "yes", "on":
		return true, nil
	case "0", "false", "no", "off", "":
		return false, nil
	default:
		return false, fmt.Errorf("expected boolean, got %q", value)
	}
}

func defaultString(value string, fallback string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return fallback
	}
	return value
}
