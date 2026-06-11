import { existsSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import {
  createWranglerConfig,
  loadAuthConfig,
  wranglerConfigPath,
  writeJsonFile,
} from "./node.js";

function findWorkspaceRoot(startDir: string): string {
  let current = resolve(startDir);

  while (true) {
    if (existsSync(join(current, "pnpm-workspace.yaml"))) return current;

    const parent = dirname(current);
    if (parent === current) {
      throw new Error(`Could not find workspace root from ${startDir}`);
    }
    current = parent;
  }
}

async function main(): Promise<void> {
  const moduleDir = dirname(fileURLToPath(import.meta.url));
  const rootDir = findWorkspaceRoot(process.env.INIT_CWD || moduleDir);
  const configPath =
    process.env.AUTH_CONFIG_PATH || join(rootDir, "config/auth.config.jsonc");
  const outputPath = wranglerConfigPath({ rootDir });

  const config = await loadAuthConfig(configPath);
  await writeJsonFile(
    outputPath,
    createWranglerConfig(config, {
      allowInsecureCallbacks:
        process.env.AUTH_REDIRECT_ALLOW_INSECURE_CALLBACKS === "true",
    })
  );

  console.log(`wrote ${outputPath}`);
}

main().catch((error: unknown) => {
  const message = error instanceof Error ? error.message : String(error);
  console.error(message);
  process.exitCode = 1;
});
