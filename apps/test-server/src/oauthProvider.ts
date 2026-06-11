import { randomBytes, randomUUID } from "node:crypto";

export type TestOAuthClient = {
  clientId: string;
  clientSecret: string;
  redirectUris: string[];
};

export type TestOAuthUser = {
  sub: string;
  name: string;
  email: string;
  email_verified: boolean;
};

export type AuthorizationRequest = {
  responseType: string | null;
  clientId: string | null;
  redirectUri: string | null;
  scope: string | null;
  state: string | null;
};

export type TokenRequest = {
  grantType: string | null;
  code: string | null;
  redirectUri: string | null;
  clientId: string | null;
  clientSecret: string | null;
};

export type AuthorizationCodeRecord = {
  code: string;
  clientId: string;
  redirectUri: string;
  scope: string;
  user: TestOAuthUser;
  expiresAt: number;
};

export type AccessTokenRecord = {
  token: string;
  clientId: string;
  scope: string;
  user: TestOAuthUser;
  expiresAt: number;
};

export type TokenResponse = {
  access_token: string;
  token_type: "Bearer";
  expires_in: number;
  scope: string;
};

const CODE_TTL_MS = 5 * 60 * 1000;
const TOKEN_TTL_MS = 60 * 60 * 1000;

export class TestOAuthProvider {
  private readonly codes = new Map<string, AuthorizationCodeRecord>();
  private readonly tokens = new Map<string, AccessTokenRecord>();

  constructor(
    private readonly client: TestOAuthClient,
    private readonly user: TestOAuthUser
  ) {
    if (client.redirectUris.length === 0) {
      throw new Error("At least one redirect URI is required");
    }
  }

  private fallbackRedirectUri(): string {
    const redirectUri = this.client.redirectUris[0];
    if (!redirectUri) throw new Error("At least one redirect URI is required");
    return redirectUri;
  }

  validateAuthorizationRequest(request: AuthorizationRequest): string | null {
    if (request.responseType !== "code") return "unsupported_response_type";
    if (request.clientId !== this.client.clientId) return "unauthorized_client";
    if (!request.redirectUri) return "invalid_request";
    if (!this.client.redirectUris.includes(request.redirectUri)) {
      return "invalid_redirect_uri";
    }

    return null;
  }

  createAuthorizationRedirect(request: AuthorizationRequest): URL {
    const error = this.validateAuthorizationRequest(request);
    if (error) {
      const fallbackRedirectUri =
        request.redirectUri && this.client.redirectUris.includes(request.redirectUri)
          ? request.redirectUri
          : this.fallbackRedirectUri();
      const url = new URL(fallbackRedirectUri);
      url.searchParams.set("error", error);
      if (request.state) url.searchParams.set("state", request.state);
      return url;
    }

    const code = randomUUID();
    this.codes.set(code, {
      code,
      clientId: request.clientId!,
      redirectUri: request.redirectUri!,
      scope: request.scope || "openid email profile",
      user: this.user,
      expiresAt: Date.now() + CODE_TTL_MS,
    });

    const url = new URL(request.redirectUri!);
    url.searchParams.set("code", code);
    if (request.state) url.searchParams.set("state", request.state);
    if (request.scope) url.searchParams.set("scope", request.scope);
    url.searchParams.set("iss", "http://localhost:4000");
    return url;
  }

  exchangeCode(request: TokenRequest): TokenResponse {
    if (request.grantType !== "authorization_code") {
      throw new Error("unsupported_grant_type");
    }
    if (
      request.clientId !== this.client.clientId ||
      request.clientSecret !== this.client.clientSecret
    ) {
      throw new Error("invalid_client");
    }
    if (!request.code || !request.redirectUri) {
      throw new Error("invalid_request");
    }

    const codeRecord = this.codes.get(request.code);
    this.codes.delete(request.code);

    if (!codeRecord || codeRecord.expiresAt < Date.now()) {
      throw new Error("invalid_grant");
    }
    if (
      codeRecord.clientId !== request.clientId ||
      codeRecord.redirectUri !== request.redirectUri
    ) {
      throw new Error("invalid_grant");
    }

    const token = randomBytes(24).toString("base64url");
    this.tokens.set(token, {
      token,
      clientId: request.clientId,
      scope: codeRecord.scope,
      user: codeRecord.user,
      expiresAt: Date.now() + TOKEN_TTL_MS,
    });

    return {
      access_token: token,
      token_type: "Bearer",
      expires_in: TOKEN_TTL_MS / 1000,
      scope: codeRecord.scope,
    };
  }

  userInfo(token: string): TestOAuthUser | null {
    const record = this.tokens.get(token);
    if (!record || record.expiresAt < Date.now()) {
      if (record) this.tokens.delete(token);
      return null;
    }

    return record.user;
  }
}

export function parseAuthorizationRequest(url: URL): AuthorizationRequest {
  return {
    responseType: url.searchParams.get("response_type"),
    clientId: url.searchParams.get("client_id"),
    redirectUri: url.searchParams.get("redirect_uri"),
    scope: url.searchParams.get("scope"),
    state: url.searchParams.get("state"),
  };
}

export function formValue(
  form: URLSearchParams,
  key: string
): string | null {
  const value = form.get(key);
  return value && value.length > 0 ? value : null;
}

export function parseTokenRequest(form: URLSearchParams): TokenRequest {
  return {
    grantType: formValue(form, "grant_type"),
    code: formValue(form, "code"),
    redirectUri: formValue(form, "redirect_uri"),
    clientId: formValue(form, "client_id"),
    clientSecret: formValue(form, "client_secret"),
  };
}
