import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import {
  createWranglerConfig,
  loadAuthConfig,
  writeJsonFile,
  wranglerConfigPath,
} from "../src/node.js";
import {
  AuthConfigSchema,
  hostMatchesPattern,
  isLocalHostname,
  isRedirectTargetAllowed,
  normalizeHostname,
  parseRuntimeConfig,
  toRuntimeConfig,
  type AuthConfig,
} from "../src/index.js";

const baseConfig: AuthConfig = AuthConfigSchema.parse({
  worker: {
    name: "ensombl-oauth-redirect-worker",
    compatibilityDate: "2025-06-17",
    observability: true,
    hostnames: ["oauth-redirect.dev.ensombl.io"],
  },
  redirects: {
    allowLocalhost: true,
    allowedHostPatterns: ["*.ensombl.io", "*.certless.io"],
    forwardedCallbackParams: ["code", "state"],
    stripTargetParams: ["redirect_uri"],
    maxStateLength: 4096,
    maxFinalUrlLength: 4096,
  },
  providers: {
    test: {
      displayName: "Local OAuth Test Server",
      authorizationEndpoint: "http://localhost:4000/oauth/authorize",
      tokenEndpoint: "http://localhost:4000/oauth/token",
      userInfoEndpoint: "http://localhost:4000/oauth/userinfo",
      scopes: ["openid", "email", "profile"],
    },
  },
});

describe("auth config", () => {
  it("matches wildcard hosts only on subdomain boundaries", () => {
    expect(hostMatchesPattern("app.ensombl.io", "*.ensombl.io")).toBe(true);
    expect(hostMatchesPattern("APP.ENSOMBL.IO.", "*.ensombl.io")).toBe(true);
    expect(hostMatchesPattern("login.ensombl.io", "login.ensombl.io")).toBe(
      true
    );
    expect(hostMatchesPattern("ensombl.io", "*.ensombl.io")).toBe(false);
    expect(hostMatchesPattern("badensombl.io", "*.ensombl.io")).toBe(false);
  });

  it("recognizes local development hosts", () => {
    expect(normalizeHostname("LOCALHOST.")).toBe("localhost");
    expect(isLocalHostname("localhost")).toBe(true);
    expect(isLocalHostname("app.localhost")).toBe(true);
    expect(isLocalHostname("127.0.0.1")).toBe(true);
    expect(isLocalHostname("127.1.2.255")).toBe(true);
    expect(isLocalHostname("127.1.2.999")).toBe(false);
    expect(isLocalHostname("::1")).toBe(true);
    expect(isLocalHostname("[::1]")).toBe(true);
    expect(isLocalHostname("127.0.0.1.example.com")).toBe(false);
  });

  it("allows configured redirect targets", () => {
    const runtimeConfig = toRuntimeConfig(baseConfig);

    expect(
      isRedirectTargetAllowed(new URL("http://localhost:3000/callback"), runtimeConfig)
    ).toBe(true);
    expect(
      isRedirectTargetAllowed(new URL("https://app.certless.io/callback"), runtimeConfig)
    ).toBe(true);
    expect(
      isRedirectTargetAllowed(new URL("https://example.com/callback"), runtimeConfig)
    ).toBe(false);
    expect(
      isRedirectTargetAllowed(new URL("http://localhost:3000/callback"), {
        redirects: {
          ...runtimeConfig.redirects,
          allowLocalhost: false,
        },
      })
    ).toBe(false);
  });

  it("parses runtime config from strings and objects", () => {
    const runtimeConfig = toRuntimeConfig(baseConfig);

    expect(parseRuntimeConfig(runtimeConfig)).toBe(runtimeConfig);
    expect(parseRuntimeConfig(JSON.stringify(runtimeConfig))).toEqual(
      runtimeConfig
    );
  });

  it("generates custom-domain Wrangler config", () => {
    const wrangler = createWranglerConfig(baseConfig);

    expect(wrangler).toMatchObject({
      name: "ensombl-oauth-redirect-worker",
      main: "../src/index.ts",
      compatibility_date: "2025-06-17",
      routes: [
        {
          pattern: "oauth-redirect.dev.ensombl.io",
          custom_domain: true,
        },
      ],
    });
    expect(wrangler.vars).toEqual({
      AUTH_REDIRECT_CONFIG: JSON.stringify(toRuntimeConfig(baseConfig)),
    });
  });

  it("includes optional account id and vars in generated Wrangler config", () => {
    const wrangler = createWranglerConfig({
      ...baseConfig,
      worker: {
        ...baseConfig.worker,
        accountId: "account-1",
        vars: {
          FEATURE_FLAG: true,
        },
      },
    });

    expect(wrangler.account_id).toBe("account-1");
    expect(wrangler.vars).toMatchObject({
      FEATURE_FLAG: true,
      AUTH_REDIRECT_CONFIG: JSON.stringify(toRuntimeConfig(baseConfig)),
    });
  });

  it("can generate a local-dev insecure callback flag", () => {
    const wrangler = createWranglerConfig(baseConfig, {
      allowInsecureCallbacks: true,
    });

    expect(wrangler.vars).toMatchObject({
      AUTH_REDIRECT_ALLOW_INSECURE_CALLBACKS: "true",
    });
  });

  it("loads JSONC config files and reports parse failures", async () => {
    const dir = await mkdtemp(join(tmpdir(), "auth-config-"));
    try {
      const configPath = join(dir, "auth.config.jsonc");
      await writeFile(
        configPath,
        `{
          // comments and trailing commas are allowed
          "worker": {
            "name": "ensombl-oauth-redirect-worker",
            "compatibilityDate": "2025-06-17",
            "hostnames": ["oauth-redirect.dev.ensombl.io"],
          },
          "redirects": {
            "allowLocalhost": true,
            "allowedHostPatterns": ["*.ensombl.io"],
            "forwardedCallbackParams": ["code", "state"],
            "stripTargetParams": ["redirect_uri"],
            "maxStateLength": 4096,
            "maxFinalUrlLength": 4096,
          },
          "providers": {
            "test": {
              "displayName": "Local OAuth Test Server",
              "authorizationEndpoint": "http://localhost:4000/oauth/authorize",
              "tokenEndpoint": "http://localhost:4000/oauth/token",
              "scopes": ["openid"]
            }
          }
        }`
      );

      const loaded = await loadAuthConfig(configPath);
      expect(loaded.worker.observability).toBe(true);
      expect(loaded.providers.test?.scopes).toEqual(["openid"]);

      const invalidPath = join(dir, "invalid.jsonc");
      await writeFile(invalidPath, "{");
      await expect(loadAuthConfig(invalidPath)).rejects.toThrow(
        "Invalid JSONC"
      );
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it("writes JSON files and resolves the generated Wrangler config path", async () => {
    const dir = await mkdtemp(join(tmpdir(), "auth-config-write-"));
    try {
      const outputPath = join(dir, "nested", "file.json");
      await writeJsonFile(outputPath, { ok: true });

      await expect(readFile(outputPath, "utf8")).resolves.toBe(
        '{\n  "ok": true\n}\n'
      );
      expect(wranglerConfigPath({ rootDir: dir })).toBe(
        join(dir, "apps/oauth-redirect-worker/.generated", "wrangler.jsonc")
      );
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });
});
