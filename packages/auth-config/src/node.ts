import { mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import {
  type ParseError,
  parse,
  printParseErrorCode,
} from "jsonc-parser";
import {
  AuthConfigSchema,
  type AuthConfig,
  toRuntimeConfig,
} from "./index.js";

export async function loadAuthConfig(path: string): Promise<AuthConfig> {
  const source = await readFile(path, "utf8");
  const errors: ParseError[] = [];
  const parsed = parse(source, errors, {
    allowTrailingComma: true,
    disallowComments: false,
  }) as unknown;

  if (errors.length > 0) {
    const detail = errors
      .map((error) => `${printParseErrorCode(error.error)} at ${error.offset}`)
      .join(", ");
    throw new Error(`Invalid JSONC in ${path}: ${detail}`);
  }

  return AuthConfigSchema.parse(parsed);
}

export function createWranglerConfig(
  config: AuthConfig,
  options: { allowInsecureCallbacks?: boolean } = {}
): Record<string, unknown> {
  const wranglerConfig: Record<string, unknown> = {
    $schema: "../node_modules/wrangler/config-schema.json",
    name: config.worker.name,
    main: "../src/index.ts",
    compatibility_date: config.worker.compatibilityDate,
    observability: {
      enabled: config.worker.observability,
    },
    routes: config.worker.hostnames.map((hostname) => ({
      pattern: hostname,
      custom_domain: true,
    })),
    vars: {
      AUTH_REDIRECT_CONFIG: JSON.stringify(toRuntimeConfig(config)),
      ...(options.allowInsecureCallbacks
        ? { AUTH_REDIRECT_ALLOW_INSECURE_CALLBACKS: "true" }
        : {}),
      ...(config.worker.vars ?? {}),
    },
  };

  if (config.worker.accountId) {
    wranglerConfig.account_id = config.worker.accountId;
  }

  return wranglerConfig;
}

export async function writeJsonFile(
  path: string,
  value: unknown
): Promise<void> {
  await mkdir(dirname(path), { recursive: true });
  await writeFile(path, `${JSON.stringify(value, null, 2)}\n`);
}

export function wranglerConfigPath(options: {
  rootDir: string;
}): string {
  return join(
    options.rootDir,
    "apps/oauth-redirect-worker/.generated",
    "wrangler.jsonc"
  );
}
