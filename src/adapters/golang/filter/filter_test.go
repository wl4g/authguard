package filter

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"authguard/adapters/golang/access"
	"authguard/adapters/golang/model"
	"authguard/adapters/golang/util"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

const testSigningKey = "test-access-context-hmac-key-32-bytes-minimum"

type scopeClientFunc func(context.Context, string) (string, error)

func (f scopeClientFunc) ResolveScope(ctx context.Context, token string) (string, error) {
	return f(ctx, token)
}

func TestHeaderContextResolverSetsRequestAccess(t *testing.T) {
	encoded := mustSign(t, sampleAccessContext())
	ctx, authenticated, err := directFilter(t).EnterHeaders(context.Background(), encoded, "")
	assertAuthenticated(t, ctx, authenticated, err)
}

func TestGRPCContextResolverResolvesOpaqueToken(t *testing.T) {
	encoded := mustEncode(t, sampleAccessContext())
	client := scopeClientFunc(func(_ context.Context, token string) (string, error) {
		if token != "ags_scope" {
			t.Fatalf("unexpected token %q", token)
		}
		return encoded, nil
	})
	filter := NewAccessFilter(
		directResolver(t),
		access.NewGRPCAccessContextResolver(client),
	)
	ctx, authenticated, err := filter.EnterHeaders(context.Background(), "", "ags_scope")
	assertAuthenticated(t, ctx, authenticated, err)
}

func TestMissingAccessHeadersRemainUnauthenticated(t *testing.T) {
	ctx, authenticated, err := NewAccessFilter().EnterHeaders(context.Background(), "", "")
	assertNoAuthentication(t, ctx, authenticated, err)
}

func TestMalformedDirectContextFailsClosed(t *testing.T) {
	_, authenticated, err := directFilter(t).EnterHeaders(context.Background(), "not-base64!", "")
	if err == nil || authenticated {
		t.Fatalf("expected invalid direct context, authenticated=%t err=%v", authenticated, err)
	}
}

func TestUnsupportedDirectContextVersionFailsClosed(t *testing.T) {
	contextValue := sampleAccessContext()
	contextValue.Version = 2
	_, authenticated, err := directFilter(t).EnterHeaders(
		context.Background(), signUnchecked(t, contextValue), "",
	)
	if err == nil || authenticated {
		t.Fatalf("expected unsupported context, authenticated=%t err=%v", authenticated, err)
	}
}

func TestExpiredDirectContextFailsClosed(t *testing.T) {
	contextValue := sampleAccessContext()
	contextValue.IssuedAtEpochSec = 1
	contextValue.ExpiresAtEpochSec = 2
	_, authenticated, err := directFilter(t).EnterHeaders(
		context.Background(), signUnchecked(t, contextValue), "",
	)
	if err == nil || authenticated {
		t.Fatalf("expected expired context, authenticated=%t err=%v", authenticated, err)
	}
}

func TestConflictingContextAndTokenHeadersFailClosed(t *testing.T) {
	_, authenticated, err := directFilter(t).EnterHeaders(
		context.Background(), mustSign(t, sampleAccessContext()), "ags_scope",
	)
	if !errors.Is(err, ErrConflictingAccessHeaders) || authenticated {
		t.Fatalf("expected conflicting headers, authenticated=%t err=%v", authenticated, err)
	}
}

func TestScopeResolverFailureFailsClosed(t *testing.T) {
	client := scopeClientFunc(func(context.Context, string) (string, error) {
		return "", errors.New("scope service unavailable")
	})
	_, authenticated, err := NewAccessFilter(access.NewGRPCAccessContextResolver(client)).EnterHeaders(
		context.Background(), "", "ags_scope",
	)
	if err == nil || authenticated {
		t.Fatalf("expected resolver failure, authenticated=%t err=%v", authenticated, err)
	}
}

func TestScopeTokenWithoutRequestResolverFailsClosed(t *testing.T) {
	_, authenticated, err := NewAccessFilter().EnterHeaders(context.Background(), "", "ags_scope")
	if !errors.Is(err, access.ErrScopeResolverUnavailable) || authenticated {
		t.Fatalf("expected missing resolver, authenticated=%t err=%v", authenticated, err)
	}
}

func TestMalformedResolvedContextFailsClosed(t *testing.T) {
	client := scopeClientFunc(func(context.Context, string) (string, error) {
		return "not-base64!", nil
	})
	_, authenticated, err := NewAccessFilter(access.NewGRPCAccessContextResolver(client)).EnterHeaders(
		context.Background(), "", "ags_scope",
	)
	if err == nil || authenticated {
		t.Fatalf("expected malformed resolved context, authenticated=%t err=%v", authenticated, err)
	}
}

func TestDirectContextDoesNotCallScopeService(t *testing.T) {
	client := scopeClientFunc(func(context.Context, string) (string, error) {
		t.Fatal("scope service must not be called")
		return "", nil
	})
	ctx, authenticated, err := NewAccessFilter(
		directResolver(t), access.NewGRPCAccessContextResolver(client),
	).EnterHeaders(context.Background(), mustSign(t, sampleAccessContext()), "")
	assertAuthenticated(t, ctx, authenticated, err)
}

func TestSecondEntryDoesNotReusePreviousRequestAccess(t *testing.T) {
	filter := directFilter(t)
	first, authenticated, err := filter.EnterHeaders(
		context.Background(), mustSign(t, sampleAccessContext()), "",
	)
	assertAuthenticated(t, first, authenticated, err)

	second, authenticated, err := filter.EnterHeaders(first, "", "")
	assertNoAuthentication(t, second, authenticated, err)
}

func TestFrameworkAdapterScopesDirectContextToRequest(t *testing.T) {
	middleware := NewAccessMiddleware(directResolver(t))
	handler := middleware.Wrap(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if _, ok := access.RequestAccess(request.Context()); !ok {
			t.Fatal("request access missing")
		}
		response.WriteHeader(http.StatusNoContent)
	}))
	request := httptest.NewRequest(http.MethodGet, "/jobs", nil)
	request.Header.Set(util.AccessContextHeader, mustSign(t, sampleAccessContext()))
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusNoContent {
		t.Fatalf("unexpected status %d", response.Code)
	}
}

func TestFrameworkAdapterRejectsMissingAccessContext(t *testing.T) {
	handler := NewAccessMiddleware().Wrap(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("upstream handler must not run")
	}))
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/jobs", nil))

	if response.Code != http.StatusUnauthorized {
		t.Fatalf("unexpected status %d", response.Code)
	}
}

func TestFrameworkAdapterResolvesScopeToken(t *testing.T) {
	client := scopeClientFunc(func(_ context.Context, token string) (string, error) {
		if token != "ags_scope" {
			t.Fatalf("unexpected token %q", token)
		}
		return mustEncode(t, sampleAccessContext()), nil
	})
	middleware := NewAccessMiddleware(access.NewGRPCAccessContextResolver(client))
	handler := middleware.Wrap(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		requestAccess, ok := access.RequestAccess(request.Context())
		if !ok || requestAccess.PrincipalID != "revenue-analyst" {
			t.Fatalf("unexpected request access: %#v", requestAccess)
		}
		response.WriteHeader(http.StatusNoContent)
	}))
	request := httptest.NewRequest(http.MethodGet, "/jobs", nil)
	request.Header.Set(util.ScopeTokenHeader, "ags_scope")
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusNoContent {
		t.Fatalf("unexpected status %d", response.Code)
	}
}

func TestGRPCTargetConfigurationUsesStandardEnvironmentNames(t *testing.T) {
	if access.GRPCTargetEnv != "AUTHGUARD_GRPC_TARGET" || access.GRPCTLSEnv != "AUTHGUARD_GRPC_TLS" {
		t.Fatalf(
			"unexpected environment contract: %s %s",
			access.GRPCTargetEnv,
			access.GRPCTLSEnv,
		)
	}
}

func TestGRPCClientAcceptsExplicitInternalTargetWithoutConnecting(t *testing.T) {
	client, err := access.NewGRPCScopeTokenClient(
		"authguard.authguard.svc.cluster.local:8080",
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestGRPCClientInitializesFromEnvironmentWithoutConnecting(t *testing.T) {
	t.Setenv(access.GRPCTargetEnv, "authguard.authguard.svc.cluster.local:8080")
	t.Setenv(access.GRPCTLSEnv, "false")
	client, err := access.NewGRPCScopeTokenClientFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestUnsignedDirectContextFailsClosed(t *testing.T) {
	_, authenticated, err := directFilter(t).EnterHeaders(
		context.Background(), mustEncode(t, sampleAccessContext()), "",
	)
	if err == nil || authenticated {
		t.Fatalf("expected unsigned context rejection, authenticated=%t err=%v", authenticated, err)
	}
}

func TestTamperedDirectContextFailsClosed(t *testing.T) {
	signed := mustSign(t, sampleAccessContext())
	tampered := strings.Replace(signed, "agctx1.", "agctx1.A", 1)
	_, authenticated, err := directFilter(t).EnterHeaders(context.Background(), tampered, "")
	if err == nil || authenticated {
		t.Fatalf("expected tampered context rejection, authenticated=%t err=%v", authenticated, err)
	}
}

func TestDirectContextSignedWithDifferentKeyFailsClosed(t *testing.T) {
	signed, err := util.SignAccessContext(
		sampleAccessContext(), "different-access-context-hmac-key-32-bytes-minimum",
	)
	if err != nil {
		t.Fatal(err)
	}
	_, authenticated, err := directFilter(t).EnterHeaders(context.Background(), signed, "")
	if err == nil || authenticated {
		t.Fatalf("expected wrong-key rejection, authenticated=%t err=%v", authenticated, err)
	}
}

func TestSigningKeyConfigurationUsesStandardEnvironmentName(t *testing.T) {
	if access.AccessContextHMACKeyEnv != "AUTHGUARD_ACCESS_CONTEXT_HMAC_KEY" {
		t.Fatalf("unexpected signing key environment: %s", access.AccessContextHMACKeyEnv)
	}
}

func assertAuthenticated(t *testing.T, ctx context.Context, authenticated bool, err error) {
	t.Helper()
	if err != nil || !authenticated {
		t.Fatalf("unexpected filter result: authenticated=%t err=%v", authenticated, err)
	}
	requestAccess, ok := access.RequestAccess(ctx)
	if !ok || requestAccess.PrincipalID != "revenue-analyst" ||
		requestAccess.Action != "customer-growth.job.read" {
		t.Fatalf("unexpected request access: %#v", requestAccess)
	}
}

func assertNoAuthentication(t *testing.T, ctx context.Context, authenticated bool, err error) {
	t.Helper()
	if err != nil || authenticated {
		t.Fatalf("unexpected filter result: authenticated=%t err=%v", authenticated, err)
	}
	if _, ok := access.RequestAccess(ctx); ok {
		t.Fatal("request access must be absent")
	}
}

func mustEncode(t *testing.T, accessContext model.AccessContext) string {
	t.Helper()
	encoded, err := util.EncodeAccessContext(accessContext)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func mustSign(t *testing.T, accessContext model.AccessContext) string {
	t.Helper()
	signed, err := util.SignAccessContext(accessContext, testSigningKey)
	if err != nil {
		t.Fatal(err)
	}
	return signed
}

func encodeUnchecked(t *testing.T, accessContext model.AccessContext) string {
	t.Helper()
	payload, err := json.Marshal(accessContext)
	if err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(payload)
}

func signUnchecked(t *testing.T, accessContext model.AccessContext) string {
	t.Helper()
	signed, err := util.SignEncodedAccessContext(encodeUnchecked(t, accessContext), testSigningKey)
	if err != nil {
		t.Fatal(err)
	}
	return signed
}

func directResolver(t *testing.T) access.HeaderAccessContextResolver {
	t.Helper()
	resolver, err := access.NewHeaderAccessContextResolver(testSigningKey)
	if err != nil {
		t.Fatal(err)
	}
	return resolver
}

func directFilter(t *testing.T) AccessFilter {
	t.Helper()
	return NewAccessFilter(directResolver(t))
}

func sampleAccessContext() model.AccessContext {
	return model.NewAccessContext(
		"revenue-analyst",
		"customer-growth.job.read",
		"urn:iam:prod:customer-growth:global:example-corp:workspace/customer-insights/project/retention-analytics/job/daily-churn-risk-score",
		[]string{"urn:iam:prod:customer-growth:global:example-corp:workspace/customer-insights/project/retention-analytics/job/*"},
		[]string{"urn:iam:prod:customer-growth:global:example-corp:workspace/customer-insights/project/retention-analytics/job/vip-retention-risk-audit"},
		1,
		30*time.Second,
	)
}
