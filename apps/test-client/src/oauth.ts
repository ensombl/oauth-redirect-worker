import type { AuthConfig, OAuthProviderConfig } from "@ensombl/auth-config";

export type ProviderRuntimeConfig = OAuthProviderConfig & {
  id: string;
  clientId: string;
  clientSecret: string;
  enabled: boolean;
};

export type LoginState = {
  redirect_uri: string;
  provider: string;
  nonce: string;
  return_to?: string;
};

export type TokenResponse = {
  access_token?: string;
  expires_in?: number;
  id_token?: string;
  refresh_token?: string;
  scope?: string;
  token_type?: string;
  [key: string]: unknown;
};

export type FetchLike = typeof fetch;

export function loadProviderRuntimeConfigs(
  config: AuthConfig
): ProviderRuntimeConfig[] {
  return Object.entries(config.providers).map(([id, provider]) => {
    const clientId = provider.clientId ?? "";
    const clientSecret = provider.clientSecret ?? "";

    return {
      id,
      ...provider,
      clientId,
      clientSecret,
      enabled: clientId.length > 0 && clientSecret.length > 0,
    };
  });
}

export function buildTargetRedirectUri(
  testClientBaseUrl: string,
  providerId: string
): string {
  return new URL(`/callback/${providerId}`, testClientBaseUrl).toString();
}

export function buildWorkerRedirectUri(
  authWorkerBaseUrl: string,
  providerId: string
): string {
  return new URL(`/callback/${providerId}`, authWorkerBaseUrl).toString();
}

export function createLoginState(options: {
  redirectUri: string;
  providerId: string;
  nonce: string;
  returnTo?: string | null;
}): string {
  const returnTo = normalizeReturnTo(options.returnTo);
  return JSON.stringify({
    redirect_uri: options.redirectUri,
    provider: options.providerId,
    nonce: options.nonce,
    ...(returnTo ? { return_to: returnTo } : {}),
  } satisfies LoginState);
}

export function normalizeReturnTo(value: string | null | undefined): string | null {
  if (!value) return null;
  if (
    value.length > 2048 ||
    !value.startsWith("/") ||
    value.startsWith("//") ||
    value.includes("\\")
  ) {
    throw new Error("Invalid return_to");
  }

  const parsed = new URL(value, "http://localhost");
  if (parsed.origin !== "http://localhost") {
    throw new Error("Invalid return_to");
  }

  return `${parsed.pathname}${parsed.search}${parsed.hash}`;
}

export function appendLoginToReturnTo(returnTo: string, loginId: string): string {
  const normalized = normalizeReturnTo(returnTo);
  if (!normalized) throw new Error("Invalid return_to");

  const url = new URL(normalized, "http://localhost");
  url.searchParams.set("login", loginId);
  return `${url.pathname}${url.search}${url.hash}`;
}

export function parseLoginState(value: string): LoginState {
  const parsed = JSON.parse(value) as unknown;
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new Error("Invalid OAuth state");
  }

  const state = parsed as Partial<LoginState>;
  if (
    typeof state.redirect_uri !== "string" ||
    typeof state.provider !== "string" ||
    typeof state.nonce !== "string"
  ) {
    throw new Error("Invalid OAuth state");
  }

  if (
    typeof state.return_to !== "undefined" &&
    typeof state.return_to !== "string"
  ) {
    throw new Error("Invalid OAuth state");
  }

  const returnTo = normalizeReturnTo(state.return_to);

  return {
    redirect_uri: state.redirect_uri,
    provider: state.provider,
    nonce: state.nonce,
    ...(returnTo ? { return_to: returnTo } : {}),
  };
}

export function buildAuthorizationUrl(options: {
  provider: ProviderRuntimeConfig;
  redirectUri: string;
  state: string;
}): string {
  const url = new URL(options.provider.authorizationEndpoint);
  url.searchParams.set("response_type", "code");
  url.searchParams.set("client_id", options.provider.clientId);
  url.searchParams.set("redirect_uri", options.redirectUri);
  url.searchParams.set("scope", options.provider.scopes.join(" "));
  url.searchParams.set("state", options.state);

  return url.toString();
}

export async function exchangeAuthorizationCode(options: {
  provider: ProviderRuntimeConfig;
  code: string;
  redirectUri: string;
  fetchImpl?: FetchLike;
}): Promise<TokenResponse> {
  const fetchImpl = options.fetchImpl ?? fetch;
  const body = new URLSearchParams({
    grant_type: "authorization_code",
    code: options.code,
    redirect_uri: options.redirectUri,
    client_id: options.provider.clientId,
    client_secret: options.provider.clientSecret,
  });

  const response = await fetchImpl(options.provider.tokenEndpoint, {
    method: "POST",
    headers: {
      "content-type": "application/x-www-form-urlencoded",
      accept: "application/json",
    },
    body,
  });

  const payload = (await response.json()) as TokenResponse;
  if (!response.ok) {
    const error =
      typeof payload.error === "string" ? payload.error : response.statusText;
    throw new Error(`Token exchange failed: ${error}`);
  }

  return payload;
}

export async function fetchUserInfo(options: {
  provider: ProviderRuntimeConfig;
  accessToken: string;
  fetchImpl?: FetchLike;
}): Promise<unknown> {
  if (!options.provider.userInfoEndpoint) return null;

  const fetchImpl = options.fetchImpl ?? fetch;
  const response = await fetchImpl(options.provider.userInfoEndpoint, {
    headers: {
      authorization: `Bearer ${options.accessToken}`,
      accept: "application/json",
    },
  });

  const payload = (await response.json()) as unknown;
  if (!response.ok) {
    throw new Error(`Userinfo request failed: ${response.statusText}`);
  }

  return payload;
}

export function publicTokenSummary(token: TokenResponse): Record<string, unknown> {
  return {
    token_type: token.token_type,
    scope: token.scope,
    expires_in: token.expires_in,
    has_access_token: typeof token.access_token === "string",
    has_refresh_token: typeof token.refresh_token === "string",
    has_id_token: typeof token.id_token === "string",
  };
}
