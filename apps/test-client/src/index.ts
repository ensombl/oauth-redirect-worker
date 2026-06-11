import { randomUUID } from "node:crypto";
import { existsSync } from "node:fs";
import http, { type IncomingMessage, type ServerResponse } from "node:http";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import dotenv from "dotenv";
import { loadAuthConfig } from "@ensombl/auth-config/node";
import {
  appendLoginToReturnTo,
  buildAuthorizationUrl,
  buildTargetRedirectUri,
  buildWorkerRedirectUri,
  createLoginState,
  exchangeAuthorizationCode,
  fetchUserInfo,
  loadProviderRuntimeConfigs,
  parseLoginState,
  publicTokenSummary,
  type ProviderRuntimeConfig,
} from "./oauth.js";

type PendingState = {
  providerId: string;
  createdAt: number;
};

type LoginResult = {
  provider: string;
  token: Record<string, unknown>;
  userInfo: unknown;
  state: {
    provider: string;
    redirect_uri: string;
    return_to: string | null;
  };
};

const pendingStates = new Map<string, PendingState>();
const completedLogins = new Map<string, { createdAt: number; result: LoginResult }>();
const workspaceRoot = findWorkspaceRoot(
  process.env.INIT_CWD || dirname(fileURLToPath(import.meta.url))
);

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

function loadEnv(): void {
  const path = join(workspaceRoot, ".env");
  if (existsSync(path)) dotenv.config({ path, override: false });
}

function sendHtml(res: ServerResponse, status: number, html: string): void {
  res.writeHead(status, { "content-type": "text/html; charset=utf-8" });
  res.end(html);
}

function sendJson(res: ServerResponse, status: number, payload: unknown): void {
  res.writeHead(status, { "content-type": "application/json" });
  res.end(JSON.stringify(payload, null, 2));
}

function redirect(res: ServerResponse, location: string): void {
  res.writeHead(303, { location });
  res.end();
}

function escapeHtml(value: unknown): string {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function providerPath(pathname: string, prefix: string): string | null {
  if (!pathname.startsWith(prefix)) return null;
  const providerId = pathname.slice(prefix.length).split("/")[0];
  return providerId || null;
}

function renderPage(options: {
  providers: ProviderRuntimeConfig[];
  authWorkerBaseUrl: string;
  testClientBaseUrl: string;
  result?: unknown;
  error?: string;
}): string {
  const provider = options.providers[0];
  const providerId = provider?.id ?? "provider";
  const callbackUrl = buildWorkerRedirectUri(options.authWorkerBaseUrl, providerId);
  const clientCallbackUrl = buildTargetRedirectUri(
    options.testClientBaseUrl,
    providerId
  );
  const providerName = provider?.displayName ?? "No OAuth provider";
  const loginHref = provider?.enabled ? `/auth/${provider.id}` : "#";
  const loginClass = provider?.enabled ? "login-button" : "login-button disabled";
  const loginState = provider?.enabled ? "Ready" : "Not configured";

  const result = options.result
    ? `<section><h2>Result</h2><pre>${escapeHtml(JSON.stringify(options.result, null, 2))}</pre></section>`
    : "";
  const error = options.error
    ? `<section class="error"><h2>Error</h2><pre>${escapeHtml(options.error)}</pre></section>`
    : "";

  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>OAuth Redirect Test Client</title>
  <style>
    :root {
      color-scheme: light;
      --bg: #f5f7fa;
      --panel: #ffffff;
      --line: #d5dce7;
      --text: #16202a;
      --muted: #637083;
      --accent: #147d64;
      --accent-soft: #dff4ed;
      --worker: #2454a6;
      --worker-soft: #e7eefc;
      --danger: #b42318;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      min-height: 100vh;
      background: var(--bg);
      color: var(--text);
      font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
    }
    header {
      padding: 22px 24px;
      border-bottom: 1px solid var(--line);
      background: var(--panel);
    }
    main {
      width: min(1040px, 100%);
      padding: 24px;
    }
    h1, h2 { margin: 0; letter-spacing: 0; }
    h1 { font-size: 22px; }
    h2 { margin-bottom: 12px; font-size: 16px; }
    .meta {
      display: grid;
      gap: 8px;
      margin: 18px 0 24px;
      color: var(--muted);
      font-size: 13px;
    }
    .launch {
      display: grid;
      gap: 16px;
      max-width: 420px;
      margin-top: 28px;
    }
    .login-button {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 16px;
      width: min(420px, 100%);
      min-height: 52px;
      padding: 0 16px;
      border: 1px solid #0f6b55;
      border-radius: 8px;
      background: var(--accent);
      color: white;
      text-decoration: none;
      font-weight: 700;
    }
    .login-button:not(.disabled):hover { background: #106f59; }
    .login-button.disabled {
      border-color: var(--line);
      background: #e8edf3;
      color: var(--muted);
      pointer-events: none;
    }
    small {
      color: inherit;
      opacity: 0.78;
      font-weight: 500;
    }
    .flow {
      display: grid;
      grid-template-columns:
        minmax(0, 1fr) auto minmax(0, 1fr) auto minmax(0, 1fr) auto
        minmax(0, 1fr);
      align-items: stretch;
      gap: 12px;
      max-width: 100%;
      margin-top: 22px;
    }
    .flow-node {
      display: grid;
      align-content: space-between;
      gap: 12px;
      min-height: 132px;
      padding: 14px;
      border: 1px solid var(--line);
      border-radius: 8px;
      background: var(--panel);
    }
    .flow-node.worker {
      border-color: #94b2ef;
      background: var(--worker-soft);
      box-shadow: inset 0 0 0 1px #c4d4f5;
    }
    .node-label {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 12px;
      font-size: 13px;
      font-weight: 750;
    }
    .badge {
      padding: 3px 7px;
      border-radius: 999px;
      background: var(--accent-soft);
      color: #0d5d4a;
      font-size: 11px;
      font-weight: 700;
    }
    .worker .badge {
      background: #d4e1fb;
      color: var(--worker);
    }
    .endpoint {
      display: block;
      overflow-wrap: anywhere;
      color: var(--muted);
      font-family: ui-monospace, "SFMono-Regular", Menlo, Consolas, monospace;
      font-size: 12px;
      line-height: 1.45;
    }
    .connector {
      display: grid;
      align-items: center;
      color: var(--muted);
      font-size: 20px;
      font-weight: 700;
    }
    section {
      margin-top: 28px;
    }
    pre {
      overflow: auto;
      padding: 14px;
      border: 1px solid var(--line);
      border-radius: 8px;
      background: var(--panel);
      font-size: 13px;
      line-height: 1.5;
    }
    .error h2 { color: var(--danger); }
    @media (max-width: 820px) {
      .flow {
        grid-template-columns: 1fr;
      }
      .connector {
        justify-items: center;
        transform: rotate(90deg);
        min-height: 20px;
      }
    }
  </style>
</head>
<body>
  <header><h1>OAuth Redirect Test Client</h1></header>
  <main>
    <div class="meta">
      <div>Client: ${escapeHtml(options.testClientBaseUrl)}</div>
      <div>Worker: ${escapeHtml(options.authWorkerBaseUrl)}</div>
    </div>
    <section class="launch">
      <a class="${loginClass}" href="${escapeHtml(loginHref)}" aria-disabled="${!provider?.enabled}">
        <span>Start local OAuth login</span>
        <small>${escapeHtml(providerName)} - ${escapeHtml(loginState)}</small>
      </a>
    </section>
    <section>
      <h2>OAuth Route</h2>
      <div class="flow" aria-label="OAuth redirect route">
        <div class="flow-node">
          <div class="node-label"><span>Test Client</span><span class="badge">start</span></div>
          <code class="endpoint">${escapeHtml(new URL(loginHref, options.testClientBaseUrl).toString())}</code>
        </div>
        <div class="connector">-&gt;</div>
        <div class="flow-node">
          <div class="node-label"><span>OAuth Test Server</span><span class="badge">authorize</span></div>
          <code class="endpoint">${escapeHtml(provider?.authorizationEndpoint ?? "not configured")}</code>
        </div>
        <div class="connector">-&gt;</div>
        <div class="flow-node worker">
          <div class="node-label"><span>Redirect Worker</span><span class="badge">redirect_uri</span></div>
          <code class="endpoint">${escapeHtml(callbackUrl)}</code>
        </div>
        <div class="connector">-&gt;</div>
        <div class="flow-node">
          <div class="node-label"><span>Test Client</span><span class="badge">callback</span></div>
          <code class="endpoint">${escapeHtml(clientCallbackUrl)}</code>
        </div>
      </div>
    </section>
    ${error}
    ${result}
  </main>
</body>
</html>`;
}

loadEnv();

const port = Number(process.env.PORT || 3000);
const testClientBaseUrl =
  process.env.TEST_CLIENT_BASE_URL || `http://localhost:${port}`;
const authWorkerBaseUrl =
  process.env.AUTH_WORKER_BASE_URL || "http://localhost:8787";
const configPath =
  process.env.AUTH_CONFIG_PATH ||
  join(workspaceRoot, "config/auth.config.jsonc");

const authConfig = await loadAuthConfig(configPath);
const providers = loadProviderRuntimeConfigs(authConfig);

const server = http.createServer((req, res) => {
  void handleRequest(req, res).catch((error: unknown) => {
    const message = error instanceof Error ? error.message : String(error);
    sendHtml(
      res,
      500,
      renderPage({
        providers,
        authWorkerBaseUrl,
        testClientBaseUrl,
        error: message,
      })
    );
  });
});

async function handleRequest(
  req: IncomingMessage,
  res: ServerResponse
): Promise<void> {
  const url = new URL(req.url || "/", testClientBaseUrl);

  if (req.method === "GET" && url.pathname === "/health") {
    sendJson(res, 200, { status: "ok" });
    return;
  }

  const authProvider = providerPath(url.pathname, "/auth/");
  if (req.method === "GET" && authProvider) {
    startLogin(authProvider, url, res);
    return;
  }

  const callbackProvider = providerPath(url.pathname, "/callback/");
  if (req.method === "GET" && callbackProvider) {
    await finishLogin(callbackProvider, url, res);
    return;
  }

  const completedLogin = loginResult(url);
  if (req.method === "GET" && completedLogin) {
    sendHtml(
      res,
      200,
      renderPage({
        providers,
        authWorkerBaseUrl,
        testClientBaseUrl,
        result: completedLogin,
      })
    );
    return;
  }

  if (req.method === "GET" && url.pathname === "/") {
    sendHtml(
      res,
      200,
      renderPage({ providers, authWorkerBaseUrl, testClientBaseUrl })
    );
    return;
  }

  sendJson(res, 404, { error: "not found" });
}

function loginResult(url: URL): LoginResult | null {
  const loginId = url.searchParams.get("login");
  if (!loginId) return null;
  return completedLogins.get(loginId)?.result ?? null;
}

function providerById(providerId: string): ProviderRuntimeConfig {
  const provider = providers.find((candidate) => candidate.id === providerId);
  if (!provider) throw new Error(`Unknown provider: ${providerId}`);
  if (!provider.enabled) throw new Error(`Provider is not configured: ${providerId}`);
  return provider;
}

function startLogin(providerId: string, url: URL, res: ServerResponse): void {
  const provider = providerById(providerId);
  const nonce = randomUUID();
  const targetRedirectUri = buildTargetRedirectUri(testClientBaseUrl, providerId);
  const workerRedirectUri = buildWorkerRedirectUri(authWorkerBaseUrl, providerId);
  const state = createLoginState({
    redirectUri: targetRedirectUri,
    providerId,
    nonce,
    returnTo: url.searchParams.get("return_to"),
  });

  pendingStates.set(nonce, { providerId, createdAt: Date.now() });

  redirect(
    res,
    buildAuthorizationUrl({
      provider,
      redirectUri: workerRedirectUri,
      state,
    })
  );
}

async function finishLogin(
  providerId: string,
  url: URL,
  res: ServerResponse
): Promise<void> {
  const provider = providerById(providerId);
  const stateParam = url.searchParams.get("state");
  if (!stateParam) throw new Error("Missing OAuth state");

  const state = parseLoginState(stateParam);
  const pending = pendingStates.get(state.nonce);
  pendingStates.delete(state.nonce);

  if (!pending || pending.providerId !== providerId || state.provider !== providerId) {
    throw new Error("OAuth state check failed");
  }

  const providerError = url.searchParams.get("error");
  if (providerError) {
    sendHtml(
      res,
      200,
      renderPage({
        providers,
        authWorkerBaseUrl,
        testClientBaseUrl,
        error: `${providerError}: ${url.searchParams.get("error_description") || ""}`,
      })
    );
    return;
  }

  const code = url.searchParams.get("code");
  if (!code) throw new Error("Missing OAuth authorization code");

  const workerRedirectUri = buildWorkerRedirectUri(authWorkerBaseUrl, providerId);
  const token = await exchangeAuthorizationCode({
    provider,
    code,
    redirectUri: workerRedirectUri,
  });
  const userInfo =
    typeof token.access_token === "string"
      ? await fetchUserInfo({ provider, accessToken: token.access_token })
      : null;
  const result: LoginResult = {
    provider: provider.id,
    token: publicTokenSummary(token),
    userInfo,
    state: {
      provider: state.provider,
      redirect_uri: state.redirect_uri,
      return_to: state.return_to ?? null,
    },
  };

  if (state.return_to) {
    completedLogins.set(state.nonce, { createdAt: Date.now(), result });
    redirect(res, appendLoginToReturnTo(state.return_to, state.nonce));
    return;
  }

  sendHtml(
    res,
    200,
    renderPage({
      providers,
      authWorkerBaseUrl,
      testClientBaseUrl,
      result,
    })
  );
}

server.listen(port, () => {
  console.log(`oauth test client listening on ${testClientBaseUrl}`);
});
