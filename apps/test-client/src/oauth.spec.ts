import { describe, expect, it } from "vitest";
import type { AuthConfig } from "@ensombl/auth-config";
import {
  appendLoginToReturnTo,
  buildAuthorizationUrl,
  buildTargetRedirectUri,
  buildWorkerRedirectUri,
  createLoginState,
  exchangeAuthorizationCode,
  fetchUserInfo,
  loadProviderRuntimeConfigs,
  normalizeReturnTo,
  parseLoginState,
  publicTokenSummary,
  type ProviderRuntimeConfig,
} from "./oauth.js";

const authConfig: AuthConfig = {
  worker: {
    name: "oauth-redirect",
    compatibilityDate: "2025-06-17",
    observability: true,
    hostnames: ["oauth-redirect.dev.ensombl.io"],
  },
  redirects: {
    allowLocalhost: true,
    allowedHostPatterns: ["*.ensombl.io"],
    forwardedCallbackParams: ["code", "state"],
    stripTargetParams: ["redirect_uri"],
    maxStateLength: 4096,
    maxFinalUrlLength: 4096,
  },
  providers: {
    test: {
      displayName: "Local OAuth Test Server",
      clientId: "test-client",
      clientSecret: "test-secret",
      authorizationEndpoint: "http://localhost:4000/oauth/authorize",
      tokenEndpoint: "http://localhost:4000/oauth/token",
      userInfoEndpoint: "http://localhost:4000/oauth/userinfo",
      scopes: ["openid", "email", "profile"],
    },
  },
};

const testProvider: ProviderRuntimeConfig = {
  id: "test",
  displayName: "Local OAuth Test Server",
  authorizationEndpoint: "http://localhost:4000/oauth/authorize",
  tokenEndpoint: "http://localhost:4000/oauth/token",
  userInfoEndpoint: "http://localhost:4000/oauth/userinfo",
  scopes: ["openid", "email", "profile"],
  clientId: "client-id",
  clientSecret: "client-secret",
  enabled: true,
};

describe("oauth test client helpers", () => {
  it("loads providers from config credentials", () => {
    const providers = loadProviderRuntimeConfigs(authConfig);

    expect(providers).toHaveLength(1);
    expect(providers[0]).toMatchObject({
      id: "test",
      clientId: "test-client",
      clientSecret: "test-secret",
      enabled: true,
    });
  });

  it("marks providers without credentials as disabled", () => {
    const providers = loadProviderRuntimeConfigs({
      ...authConfig,
      providers: {
        test: {
          ...authConfig.providers.test!,
          clientId: undefined,
          clientSecret: undefined,
        },
      },
    });

    expect(providers[0]).toMatchObject({
      clientId: "",
      clientSecret: "",
      enabled: false,
    });
  });

  it("applies OAuth client env overrides to the default provider", () => {
    const providers = loadProviderRuntimeConfigs(authConfig, {
      OAUTH_CLIENT_ID: "env-client",
      OAUTH_CLIENT_SECRET: "env-secret",
      OAUTH_SCOPES: "openid,email,profile",
    });

    expect(providers).toHaveLength(1);
    expect(providers[0]).toMatchObject({
      id: "test",
      displayName: "Local OAuth Test Server",
      clientId: "env-client",
      clientSecret: "env-secret",
      scopes: ["openid", "email", "profile"],
      enabled: true,
    });
  });

  it("supports a Google OAuth provider from env", () => {
    const providers = loadProviderRuntimeConfigs(authConfig, {
      OAUTH_PROVIDER_ID: "google",
      OAUTH_CLIENT_ID: "google-client",
      OAUTH_CLIENT_SECRET: "google-secret",
    });

    expect(providers).toEqual([
      expect.objectContaining({
        id: "google",
        displayName: "Google",
        clientId: "google-client",
        clientSecret: "google-secret",
        authorizationEndpoint: "https://accounts.google.com/o/oauth2/v2/auth",
        tokenEndpoint: "https://oauth2.googleapis.com/token",
        userInfoEndpoint: "https://openidconnect.googleapis.com/v1/userinfo",
        scopes: ["openid", "email", "profile"],
        enabled: true,
      }),
    ]);
  });

  it("does not inherit mock endpoints for unknown env provider ids", () => {
    const providers = loadProviderRuntimeConfigs(authConfig, {
      OAUTH_PROVIDER_ID: "custom",
      OAUTH_CLIENT_ID: "custom-client",
      OAUTH_CLIENT_SECRET: "custom-secret",
    });

    expect(providers[0]).toMatchObject({
      id: "custom",
      authorizationEndpoint: "",
      tokenEndpoint: "",
      enabled: false,
    });
  });

  it("builds worker and target redirect URIs", () => {
    expect(buildTargetRedirectUri("http://localhost:3000", "test")).toBe(
      "http://localhost:3000/callback/test"
    );
    expect(
      buildWorkerRedirectUri("https://oauth-redirect.dev.ensombl.io", "test")
    ).toBe("https://oauth-redirect.dev.ensombl.io/callback/test");
  });

  it("creates and parses login state", () => {
    const redirectUri = "http://localhost:3000/callback/test";
    const state = createLoginState({
      redirectUri,
      providerId: "test",
      nonce: "nonce-1",
      returnTo: "/dashboard?tab=home&view=full",
    });

    expect(parseLoginState(state)).toEqual({
      redirect_uri: redirectUri,
      provider: "test",
      nonce: "nonce-1",
      return_to: "/dashboard?tab=home&view=full",
    });
  });

  it("rejects malformed login state", () => {
    expect(() => parseLoginState("null")).toThrow("Invalid OAuth state");
    expect(() => parseLoginState("[]")).toThrow("Invalid OAuth state");
    expect(() =>
      parseLoginState(JSON.stringify({ redirect_uri: "http://localhost" }))
    ).toThrow("Invalid OAuth state");
    expect(() =>
      parseLoginState(
        JSON.stringify({
          redirect_uri: "http://localhost:3000/callback/test",
          provider: "test",
          nonce: "nonce-1",
          return_to: "https://evil.test",
        })
      )
    ).toThrow("Invalid return_to");
    expect(() =>
      parseLoginState(
        JSON.stringify({
          redirect_uri: "http://localhost:3000/callback/test",
          provider: "test",
          nonce: "nonce-1",
          return_to: 123,
        })
      )
    ).toThrow("Invalid OAuth state");
  });

  it("normalizes only relative return_to targets", () => {
    expect(normalizeReturnTo("/dashboard?tab=home#top")).toBe(
      "/dashboard?tab=home#top"
    );
    expect(normalizeReturnTo(null)).toBeNull();
    expect(normalizeReturnTo("")).toBeNull();
    expect(() => normalizeReturnTo("https://evil.test")).toThrow(
      "Invalid return_to"
    );
    expect(() => normalizeReturnTo("//evil.test/path")).toThrow(
      "Invalid return_to"
    );
    expect(() => normalizeReturnTo("/\\evil")).toThrow("Invalid return_to");
  });

  it("appends local login handles to return_to targets", () => {
    expect(appendLoginToReturnTo("/dashboard", "nonce-1")).toBe(
      "/dashboard?login=nonce-1"
    );
    expect(appendLoginToReturnTo("/dashboard?tab=home#top", "nonce-1")).toBe(
      "/dashboard?tab=home&login=nonce-1#top"
    );
    expect(() => appendLoginToReturnTo("https://evil.test", "nonce-1")).toThrow(
      "Invalid return_to"
    );
  });

  it("builds provider authorization URLs", () => {
    const stateRedirectUri = "http://localhost:3000/callback/test";
    const state = createLoginState({
      redirectUri: stateRedirectUri,
      providerId: "test",
      nonce: "nonce-1",
      returnTo: "/dashboard?tab=home&view=full",
    });
    const url = new URL(
      buildAuthorizationUrl({
        provider: testProvider,
        redirectUri: "https://oauth-redirect.dev.ensombl.io/callback/test",
        state,
      })
    );

    expect(url.origin + url.pathname).toBe(
      "http://localhost:4000/oauth/authorize"
    );
    expect(url.searchParams.get("response_type")).toBe("code");
    expect(url.searchParams.get("client_id")).toBe("client-id");
    expect(url.searchParams.get("redirect_uri")).toBe(
      "https://oauth-redirect.dev.ensombl.io/callback/test"
    );
    expect(url.searchParams.get("scope")).toBe("openid email profile");
    expect(url.searchParams.get("state")).toBe(state);
    expect(parseLoginState(url.searchParams.get("state")!)).toMatchObject({
      redirect_uri: stateRedirectUri,
      return_to: "/dashboard?tab=home&view=full",
    });
  });

  it("summarizes tokens without exposing secret values", () => {
    expect(
      publicTokenSummary({
        access_token: "secret",
        refresh_token: "refresh",
        id_token: "id",
        expires_in: 3600,
        scope: "openid",
        token_type: "Bearer",
      })
    ).toEqual({
      token_type: "Bearer",
      scope: "openid",
      expires_in: 3600,
      has_access_token: true,
      has_refresh_token: true,
      has_id_token: true,
    });
  });

  it("exchanges authorization codes", async () => {
    const calls: Array<{ url: string; body: URLSearchParams }> = [];
    const fetchImpl = async (url: string | URL | Request, init?: RequestInit) => {
      calls.push({
        url: url.toString(),
        body: init?.body as URLSearchParams,
      });
      return Response.json({
        access_token: "access",
        token_type: "Bearer",
        scope: "openid",
      });
    };

    const token = await exchangeAuthorizationCode({
      provider: testProvider,
      code: "code-1",
      redirectUri: "https://oauth-redirect.dev.ensombl.io/callback/test",
      fetchImpl: fetchImpl as typeof fetch,
    });

    expect(token.access_token).toBe("access");
    expect(calls[0]?.url).toBe("http://localhost:4000/oauth/token");
    expect(calls[0]?.body.get("grant_type")).toBe("authorization_code");
    expect(calls[0]?.body.get("client_secret")).toBe("client-secret");
  });

  it("reports token exchange errors", async () => {
    const fetchImpl = async () =>
      Response.json({ error: "invalid_grant" }, { status: 400 });

    await expect(
      exchangeAuthorizationCode({
        provider: testProvider,
        code: "bad-code",
        redirectUri: "https://oauth-redirect.dev.ensombl.io/callback/test",
        fetchImpl: fetchImpl as typeof fetch,
      })
    ).rejects.toThrow("Token exchange failed: invalid_grant");

    const textErrorFetch = async () =>
      Response.json({}, { status: 500, statusText: "Server Error" });

    await expect(
      exchangeAuthorizationCode({
        provider: testProvider,
        code: "bad-code",
        redirectUri: "https://oauth-redirect.dev.ensombl.io/callback/test",
        fetchImpl: textErrorFetch as typeof fetch,
      })
    ).rejects.toThrow("Token exchange failed: Server Error");
  });

  it("fetches optional userinfo", async () => {
    expect(
      await fetchUserInfo({
        provider: {
          ...testProvider,
          userInfoEndpoint: undefined,
        },
        accessToken: "access",
      })
    ).toBeNull();

    const fetchImpl = async (url: string | URL | Request, init?: RequestInit) => {
      expect(url.toString()).toBe("http://localhost:4000/oauth/userinfo");
      expect(new Headers(init?.headers).get("authorization")).toBe(
        "Bearer access"
      );
      return Response.json({ sub: "user-1" });
    };

    await expect(
      fetchUserInfo({
        provider: testProvider,
        accessToken: "access",
        fetchImpl: fetchImpl as typeof fetch,
      })
    ).resolves.toEqual({ sub: "user-1" });

    const failedFetch = async () =>
      Response.json({ error: "invalid_token" }, { status: 401, statusText: "Unauthorized" });

    await expect(
      fetchUserInfo({
        provider: testProvider,
        accessToken: "bad",
        fetchImpl: failedFetch as typeof fetch,
      })
    ).rejects.toThrow("Userinfo request failed: Unauthorized");
  });
});
