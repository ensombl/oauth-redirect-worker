import { existsSync } from "node:fs";
import http, { type IncomingMessage, type ServerResponse } from "node:http";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import dotenv from "dotenv";
import {
  TestOAuthProvider,
  parseAuthorizationRequest,
  parseTokenRequest,
} from "./oauthProvider.js";

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

const workspaceRoot = findWorkspaceRoot(
  process.env.INIT_CWD || dirname(fileURLToPath(import.meta.url))
);
const envPath = join(workspaceRoot, ".env");
if (existsSync(envPath)) dotenv.config({ path: envPath, override: false });

const port = Number(process.env.TEST_SERVER_PORT || 4000);
const issuer = process.env.TEST_SERVER_BASE_URL || `http://localhost:${port}`;
const clientId = "test-client";
const clientSecret = "test-secret";
const redirectUris = (
  process.env.TEST_REDIRECT_URIS ||
  "http://localhost:8787/callback/test"
)
  .split(/[,\n]+/)
  .map((value) => value.trim())
  .filter((value) => value.length > 0);

const provider = new TestOAuthProvider(
  {
    clientId,
    clientSecret,
    redirectUris,
  },
  {
    sub: process.env.TEST_USER_SUB || "test-user-1",
    name: process.env.TEST_USER_NAME || "OAuth Test User",
    email: process.env.TEST_USER_EMAIL || "test-user@ensombl.local",
    email_verified: true,
  }
);

function sendJson(res: ServerResponse, status: number, payload: unknown): void {
  res.writeHead(status, {
    "content-type": "application/json",
    "cache-control": "no-store",
  });
  res.end(JSON.stringify(payload, null, 2));
}

function redirect(res: ServerResponse, location: string): void {
  res.writeHead(303, { location });
  res.end();
}

async function readForm(req: IncomingMessage): Promise<URLSearchParams> {
  const chunks: Buffer[] = [];
  for await (const chunk of req) {
    chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
  }

  return new URLSearchParams(Buffer.concat(chunks).toString("utf8"));
}

function bearerToken(req: IncomingMessage): string | null {
  const header = req.headers.authorization;
  if (!header) return null;
  const [scheme, token] = header.split(" ");
  return scheme?.toLowerCase() === "bearer" && token ? token : null;
}

const server = http.createServer((req, res) => {
  void handleRequest(req, res).catch((error: unknown) => {
    const message = error instanceof Error ? error.message : String(error);
    sendJson(res, 500, { error: "server_error", error_description: message });
  });
});

async function handleRequest(
  req: IncomingMessage,
  res: ServerResponse
): Promise<void> {
  const url = new URL(req.url || "/", issuer);

  if (req.method === "GET" && url.pathname === "/health") {
    sendJson(res, 200, { status: "ok" });
    return;
  }

  if (req.method === "GET" && url.pathname === "/.well-known/openid-configuration") {
    sendJson(res, 200, {
      issuer,
      authorization_endpoint: new URL("/oauth/authorize", issuer).toString(),
      token_endpoint: new URL("/oauth/token", issuer).toString(),
      userinfo_endpoint: new URL("/oauth/userinfo", issuer).toString(),
      response_types_supported: ["code"],
      scopes_supported: ["openid", "email", "profile"],
    });
    return;
  }

  if (req.method === "GET" && url.pathname === "/oauth/authorize") {
    redirect(
      res,
      provider
        .createAuthorizationRedirect(parseAuthorizationRequest(url))
        .toString()
    );
    return;
  }

  if (req.method === "POST" && url.pathname === "/oauth/token") {
    try {
      sendJson(res, 200, provider.exchangeCode(parseTokenRequest(await readForm(req))));
    } catch (error: unknown) {
      sendJson(res, 400, {
        error: error instanceof Error ? error.message : "invalid_request",
      });
    }
    return;
  }

  if (req.method === "GET" && url.pathname === "/oauth/userinfo") {
    const token = bearerToken(req);
    const user = token ? provider.userInfo(token) : null;
    if (!user) {
      sendJson(res, 401, { error: "invalid_token" });
      return;
    }
    sendJson(res, 200, user);
    return;
  }

  sendJson(res, 404, { error: "not_found" });
}

server.listen(port, () => {
  console.log(`oauth test server listening on ${issuer}`);
});
