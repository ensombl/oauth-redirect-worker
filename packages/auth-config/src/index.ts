import { z } from "zod";

const StringListSchema = z.array(z.string().min(1)).min(1);

const OAuthProviderSchema = z
  .object({
    displayName: z.string().min(1),
    clientId: z.string().min(1).optional(),
    clientSecret: z.string().min(1).optional(),
    authorizationEndpoint: z.url(),
    tokenEndpoint: z.url(),
    userInfoEndpoint: z.url().optional(),
    scopes: StringListSchema,
  })
  .strict();

export const AuthConfigSchema = z
  .object({
    worker: z
      .object({
        name: z.string().min(1),
        accountId: z.string().min(1).optional(),
        compatibilityDate: z.string().regex(/^\d{4}-\d{2}-\d{2}$/),
        observability: z.boolean().default(true),
        hostnames: StringListSchema,
        vars: z.record(z.string(), z.union([z.string(), z.number(), z.boolean()])).optional(),
      })
      .strict(),
    redirects: z
      .object({
        allowLocalhost: z.boolean().default(true),
        allowedHostPatterns: StringListSchema,
        forwardedCallbackParams: StringListSchema,
        stripTargetParams: StringListSchema,
        maxStateLength: z.number().int().positive(),
        maxFinalUrlLength: z.number().int().positive(),
      })
      .strict(),
    providers: z.record(z.string(), OAuthProviderSchema),
  })
  .strict();

export type AuthConfig = z.infer<typeof AuthConfigSchema>;
export type AuthRuntimeConfig = Pick<AuthConfig, "redirects">;
export type OAuthProviderConfig = z.infer<typeof OAuthProviderSchema>;

export function toRuntimeConfig(config: AuthConfig): AuthRuntimeConfig {
  return {
    redirects: config.redirects,
  };
}

export function parseRuntimeConfig(value: string | AuthRuntimeConfig): AuthRuntimeConfig {
  if (typeof value !== "string") return value;

  const parsed = JSON.parse(value) as unknown;
  return AuthConfigSchema.pick({ redirects: true }).parse(parsed);
}

export function normalizeHostname(hostname: string): string {
  let normalized = hostname.trim().toLowerCase();
  while (normalized.endsWith(".")) normalized = normalized.slice(0, -1);
  return normalized;
}

function isLoopbackIpv4(hostname: string): boolean {
  const parts = hostname.split(".");
  if (parts.length !== 4 || parts[0] !== "127") return false;

  return parts.slice(1).every((part) => {
    if (!/^\d{1,3}$/.test(part)) return false;
    const value = Number(part);
    return value >= 0 && value <= 255;
  });
}

export function isLocalHostname(hostname: string): boolean {
  const normalized = normalizeHostname(hostname);
  return (
    normalized === "localhost" ||
    normalized.endsWith(".localhost") ||
    normalized === "::1" ||
    normalized === "[::1]" ||
    isLoopbackIpv4(normalized)
  );
}

export function hostMatchesPattern(hostname: string, pattern: string): boolean {
  const normalizedHostname = normalizeHostname(hostname);
  const normalizedPattern = normalizeHostname(pattern);

  if (normalizedPattern.startsWith("*.")) {
    const suffix = normalizedPattern.slice(1);
    return (
      normalizedHostname.endsWith(suffix) &&
      normalizedHostname.length > suffix.length
    );
  }

  return normalizedHostname === normalizedPattern;
}

export function isRedirectTargetAllowed(
  target: URL,
  config: AuthRuntimeConfig
): boolean {
  if (config.redirects.allowLocalhost && isLocalHostname(target.hostname)) {
    return true;
  }

  return config.redirects.allowedHostPatterns.some((pattern) =>
    hostMatchesPattern(target.hostname, pattern)
  );
}
