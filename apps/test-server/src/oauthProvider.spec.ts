import { afterEach, describe, expect, it, vi } from "vitest";
import {
  TestOAuthProvider,
  parseAuthorizationRequest,
  parseTokenRequest,
} from "./oauthProvider.js";

const client = {
  clientId: "test-client",
  clientSecret: "test-secret",
  redirectUris: ["http://localhost:8787/callback/test"],
};

const user = {
  sub: "user-1",
  name: "Test User",
  email: "user@example.test",
  email_verified: true,
};

describe("test oauth provider", () => {
  afterEach(() => {
    vi.useRealTimers();
  });

  it("requires at least one redirect URI", () => {
    expect(
      () =>
        new TestOAuthProvider(
          {
            ...client,
            redirectUris: [],
          },
          user
        )
    ).toThrow("At least one redirect URI is required");
  });

  it("creates authorization redirects with code and state", () => {
    const provider = new TestOAuthProvider(client, user);
    const request = parseAuthorizationRequest(
      new URL(
        "http://localhost:4000/oauth/authorize?response_type=code&client_id=test-client&redirect_uri=http%3A%2F%2Flocalhost%3A8787%2Fcallback%2Ftest&scope=openid&state=state-1"
      )
    );

    const redirect = provider.createAuthorizationRedirect(request);

    expect(redirect.origin + redirect.pathname).toBe(
      "http://localhost:8787/callback/test"
    );
    expect(redirect.searchParams.get("code")).toBeTruthy();
    expect(redirect.searchParams.get("state")).toBe("state-1");
    expect(redirect.searchParams.get("scope")).toBe("openid");
  });

  it("redirects invalid authorization requests with OAuth errors", () => {
    const provider = new TestOAuthProvider(client, user);

    const unsupported = provider.createAuthorizationRedirect({
      responseType: "token",
      clientId: "test-client",
      redirectUri: "http://localhost:8787/callback/test",
      scope: null,
      state: "state-1",
    });

    expect(unsupported.origin + unsupported.pathname).toBe(
      "http://localhost:8787/callback/test"
    );
    expect(unsupported.searchParams.get("error")).toBe(
      "unsupported_response_type"
    );
    expect(unsupported.searchParams.get("state")).toBe("state-1");

    const invalidRedirect = provider.createAuthorizationRedirect({
      responseType: "code",
      clientId: "test-client",
      redirectUri: "http://evil.test/callback",
      scope: null,
      state: null,
    });

    expect(invalidRedirect.origin + invalidRedirect.pathname).toBe(
      "http://localhost:8787/callback/test"
    );
    expect(invalidRedirect.searchParams.get("error")).toBe(
      "invalid_redirect_uri"
    );

    expect(
      provider.validateAuthorizationRequest({
        responseType: "code",
        clientId: "wrong",
        redirectUri: "http://localhost:8787/callback/test",
        scope: null,
        state: null,
      })
    ).toBe("unauthorized_client");
    expect(
      provider.validateAuthorizationRequest({
        responseType: "code",
        clientId: "test-client",
        redirectUri: null,
        scope: null,
        state: null,
      })
    ).toBe("invalid_request");
  });

  it("exchanges codes exactly once", () => {
    const provider = new TestOAuthProvider(client, user);
    const redirect = provider.createAuthorizationRedirect({
      responseType: "code",
      clientId: "test-client",
      redirectUri: "http://localhost:8787/callback/test",
      scope: "openid email",
      state: "state-1",
    });
    const code = redirect.searchParams.get("code")!;

    const token = provider.exchangeCode(
      parseTokenRequest(
        new URLSearchParams({
          grant_type: "authorization_code",
          code,
          redirect_uri: "http://localhost:8787/callback/test",
          client_id: "test-client",
          client_secret: "test-secret",
        })
      )
    );

    expect(token).toMatchObject({
      token_type: "Bearer",
      scope: "openid email",
    });
    expect(provider.userInfo(token.access_token)).toEqual(user);
    expect(() =>
      provider.exchangeCode(
        parseTokenRequest(
          new URLSearchParams({
            grant_type: "authorization_code",
            code,
            redirect_uri: "http://localhost:8787/callback/test",
            client_id: "test-client",
            client_secret: "test-secret",
          })
        )
      )
    ).toThrow("invalid_grant");
  });

  it("rejects invalid token requests", () => {
    const provider = new TestOAuthProvider(client, user);

    expect(() =>
      provider.exchangeCode(
        parseTokenRequest(
          new URLSearchParams({
            grant_type: "client_credentials",
            client_id: "test-client",
            client_secret: "test-secret",
          })
        )
      )
    ).toThrow("unsupported_grant_type");

    expect(() =>
      provider.exchangeCode(
        parseTokenRequest(
          new URLSearchParams({
            grant_type: "authorization_code",
            code: "missing",
            redirect_uri: "http://localhost:8787/callback/test",
            client_id: "test-client",
            client_secret: "wrong",
          })
        )
      )
    ).toThrow("invalid_client");

    expect(() =>
      provider.exchangeCode(
        parseTokenRequest(
          new URLSearchParams({
            grant_type: "authorization_code",
            code: "",
            redirect_uri: "http://localhost:8787/callback/test",
            client_id: "test-client",
            client_secret: "test-secret",
          })
        )
      )
    ).toThrow("invalid_request");
  });

  it("rejects mismatched and expired authorization codes", () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-01-01T00:00:00.000Z"));

    const provider = new TestOAuthProvider(client, user);
    const redirect = provider.createAuthorizationRedirect({
      responseType: "code",
      clientId: "test-client",
      redirectUri: "http://localhost:8787/callback/test",
      scope: null,
      state: null,
    });
    const code = redirect.searchParams.get("code")!;

    expect(() =>
      provider.exchangeCode(
        parseTokenRequest(
          new URLSearchParams({
            grant_type: "authorization_code",
            code,
            redirect_uri: "http://localhost:8787/callback/wrong",
            client_id: "test-client",
            client_secret: "test-secret",
          })
        )
      )
    ).toThrow("invalid_grant");

    const expiredRedirect = provider.createAuthorizationRedirect({
      responseType: "code",
      clientId: "test-client",
      redirectUri: "http://localhost:8787/callback/test",
      scope: null,
      state: null,
    });
    const expiredCode = expiredRedirect.searchParams.get("code")!;
    vi.setSystemTime(new Date("2026-01-01T00:06:00.000Z"));

    expect(() =>
      provider.exchangeCode(
        parseTokenRequest(
          new URLSearchParams({
            grant_type: "authorization_code",
            code: expiredCode,
            redirect_uri: "http://localhost:8787/callback/test",
            client_id: "test-client",
            client_secret: "test-secret",
          })
        )
      )
    ).toThrow("invalid_grant");
  });

  it("expires access tokens", () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-01-01T00:00:00.000Z"));

    const provider = new TestOAuthProvider(client, user);
    const redirect = provider.createAuthorizationRedirect({
      responseType: "code",
      clientId: "test-client",
      redirectUri: "http://localhost:8787/callback/test",
      scope: null,
      state: null,
    });
    const token = provider.exchangeCode(
      parseTokenRequest(
        new URLSearchParams({
          grant_type: "authorization_code",
          code: redirect.searchParams.get("code")!,
          redirect_uri: "http://localhost:8787/callback/test",
          client_id: "test-client",
          client_secret: "test-secret",
        })
      )
    );

    vi.setSystemTime(new Date("2026-01-01T01:01:00.000Z"));
    expect(provider.userInfo(token.access_token)).toBeNull();
    expect(provider.userInfo(token.access_token)).toBeNull();
  });
});
