package filter

import (
	"context"
	"errors"
	"net/http"
	"time"

	"authguard/adapters/golang/access"
	"authguard/adapters/golang/util"
)

var ErrConflictingAccessHeaders = errors.New("both Authguard context and scope token headers are present")

type AccessRequest = access.HeaderReader

type HeaderFunc func(name string) string

func (f HeaderFunc) Header(name string) string {
	return f(name)
}

type AccessFilter struct {
	resolvers []access.IAccessContextResolver
}

func NewAccessFilter(resolvers ...access.IAccessContextResolver) AccessFilter {
	filtered := make([]access.IAccessContextResolver, 0, len(resolvers))
	for _, resolver := range resolvers {
		if resolver != nil {
			filtered = append(filtered, resolver)
		}
	}
	if len(filtered) == 0 {
		filtered = append(filtered, access.HeaderAccessContextResolver{})
	}
	return AccessFilter{resolvers: filtered}
}

func (f AccessFilter) Enter(
	ctx context.Context,
	request AccessRequest,
) (context.Context, bool, error) {
	ctx = access.WithoutGrantSet(ctx)
	directContextPresent := request.Header(util.AccessContextHeader) != ""
	scopeTokenPresent := request.Header(util.ScopeTokenHeader) != ""
	requestID := util.SafeLogString(request.Header(util.RequestIDHeader))
	util.LogDebug(ctx, "authguard.access_filter.started",
		"request_id", requestID,
		"direct_context_present", directContextPresent,
		"scope_token_present", scopeTokenPresent,
		"resolver_count", len(f.resolvers))
	if directContextPresent && scopeTokenPresent {
		util.LogDebug(ctx, "authguard.access_filter.rejected",
			"request_id", requestID, "reason", "conflicting_headers")
		return ctx, false, ErrConflictingAccessHeaders
	}
	for _, resolver := range f.resolvers {
		requestAccess, err := resolver.Resolve(ctx, request)
		if err != nil {
			util.LogDebug(ctx, "authguard.access_filter.rejected",
				"request_id", requestID, "resolver_mode", resolverMode(resolver),
				"reason", "resolver_error", "error_category", util.ErrorCategory(err))
			return ctx, false, err
		}
		if requestAccess != nil {
			util.LogDebug(ctx, "authguard.access_filter.authenticated",
				"request_id", requestID, "resolver_mode", resolverMode(resolver),
				"principal_id", util.SafeLogString(requestAccess.PrincipalID),
				"action", util.SafeLogString(requestAccess.Action),
				"allow_count", len(requestAccess.Grants.AllowResourceURNs),
				"deny_count", len(requestAccess.Grants.DenyResourceURNs))
			return access.WithRequestAccess(ctx, *requestAccess), true, nil
		}
	}
	if scopeTokenPresent {
		util.LogDebug(ctx, "authguard.access_filter.rejected",
			"request_id", requestID, "reason", "scope_resolver_unavailable")
		return ctx, false, access.ErrScopeResolverUnavailable
	}
	util.LogDebug(ctx, "authguard.access_filter.unauthenticated", "request_id", requestID)
	return ctx, false, nil
}

func resolverMode(resolver access.IAccessContextResolver) string {
	switch resolver.(type) {
	case access.HeaderAccessContextResolver, *access.HeaderAccessContextResolver:
		return "header"
	case access.GRPCAccessContextResolver, *access.GRPCAccessContextResolver:
		return "grpc"
	default:
		return "custom"
	}
}

func (f AccessFilter) EnterHeaders(
	ctx context.Context,
	encodedAccessContext string,
	scopeToken string,
) (context.Context, bool, error) {
	return f.Enter(ctx, HeaderFunc(func(name string) string {
		switch name {
		case util.AccessContextHeader:
			return encodedAccessContext
		case util.ScopeTokenHeader:
			return scopeToken
		default:
			return ""
		}
	}))
}

type AccessMiddleware struct {
	AccessFilter AccessFilter
}

func NewAccessMiddleware(resolvers ...access.IAccessContextResolver) AccessMiddleware {
	return AccessMiddleware{AccessFilter: NewAccessFilter(resolvers...)}
}

func (m AccessMiddleware) Wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		started := time.Now()
		ctx, authenticated, err := m.AccessFilter.Enter(request.Context(), HeaderFunc(request.Header.Get))
		if err != nil || !authenticated {
			reason := "access_context_missing"
			if err != nil {
				reason = "invalid_access_context"
			}
			util.LogDebug(request.Context(), "authguard.http_filter.rejected",
				"request_id", util.SafeLogString(request.Header.Get(util.RequestIDHeader)),
				"http_method", request.Method, "reason", reason,
				"error_category", util.ErrorCategory(err),
				"duration_ms", time.Since(started).Milliseconds())
			http.Error(response, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}
		requestAccess, _ := access.RequestAccess(ctx)
		util.LogDebug(ctx, "authguard.http_filter.accepted",
			"request_id", util.SafeLogString(request.Header.Get(util.RequestIDHeader)),
			"http_method", request.Method,
			"principal_id", util.SafeLogString(requestAccess.PrincipalID),
			"action", util.SafeLogString(requestAccess.Action))
		next.ServeHTTP(response, request.WithContext(ctx))
		util.LogDebug(ctx, "authguard.http_filter.completed",
			"request_id", util.SafeLogString(request.Header.Get(util.RequestIDHeader)),
			"http_method", request.Method,
			"duration_ms", time.Since(started).Milliseconds())
	})
}
