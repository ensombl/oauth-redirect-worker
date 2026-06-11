import { SELF, env } from "cloudflare:test";
import { describe, expect, it } from "vitest";
import worker from "../src/index.js";

function callbackUrl(options: {
  redirectUri?: string;
  stateExtras?: Record<string, unknown>;
  params?: Record<string, string>;
  origin?: string;
}): string {
  const url = new URL("/callback", options.origin ?? "https://worker.example.com");
  const state =
    options.redirectUri === undefined
      ? options.stateExtras
      : {
          redirect_uri: options.redirectUri,
          ...(options.stateExtras ?? {}),
        };

  if (state !== undefined) {
    url.searchParams.set("state", JSON.stringify(state));
  }

  for (const [key, value] of Object.entries(options.params ?? {})) {
    url.searchParams.set(key, value);
  }

  return url.toString();
}

function fetchCallback(url: string): Promise<Response> {
  return SELF.fetch(url, { redirect: "manual" });
}

describe("oauth redirect worker", () => {
  it("redirects OAuth callbacks to localhost targets", async () => {
    const target = "http://localhost:3000/auth/test/callback";
    const state = JSON.stringify({ redirect_uri: target, nonce: "n-1" });
    const url = new URL("/callback", "https://worker.example.com");
    url.searchParams.set("state", state);
    url.searchParams.set("code", "code-123");
    url.searchParams.set("scope", "openid email");

    const response = await fetchCallback(url.toString());

    expect(response.status).toBe(303);
    const location = new URL(response.headers.get("Location")!);
    expect(location.origin + location.pathname).toBe(target);
    expect(location.searchParams.get("code")).toBe("code-123");
    expect(location.searchParams.get("scope")).toBe("openid email");
    expect(location.searchParams.get("state")).toBe(state);
  });

  it("allows configured product subdomains and strips unsafe target params", async () => {
    const response = await fetchCallback(
      callbackUrl({
        redirectUri:
          "https://app.certless.io/auth/callback?redirect_uri=https%3A%2F%2Fevil.example&existing=1#frag",
        params: {
          code: "code-456",
          ignored: "no",
        },
      })
    );

    expect(response.status).toBe(303);
    const location = new URL(response.headers.get("Location")!);
    expect(location.origin + location.pathname).toBe(
      "https://app.certless.io/auth/callback"
    );
    expect(location.hash).toBe("");
    expect(location.searchParams.get("existing")).toBe("1");
    expect(location.searchParams.get("redirect_uri")).toBeNull();
    expect(location.searchParams.get("code")).toBe("code-456");
    expect(location.searchParams.get("ignored")).toBeNull();
  });

  it("forwards provider errors to the target", async () => {
    const response = await fetchCallback(
      callbackUrl({
        redirectUri: "https://login.ensombl.io/oauth/callback",
        params: {
          error: "access_denied",
          error_description: "No thanks",
        },
      })
    );

    expect(response.status).toBe(303);
    const location = new URL(response.headers.get("Location")!);
    expect(location.searchParams.get("error")).toBe("access_denied");
    expect(location.searchParams.get("error_description")).toBe("No thanks");
  });

  it("rejects missing or malformed state", async () => {
    const insecureOrigin = await fetchCallback(
      callbackUrl({
        origin: "http://worker.example.com",
        redirectUri: "http://localhost:3000/callback",
      })
    );
    expect(insecureOrigin.status).toBe(400);
    expect(await insecureOrigin.text()).toBe("HTTPS required");

    const devInsecureOrigin = await worker.fetch(
      new Request(
        callbackUrl({
          origin: "http://worker.example.com",
          redirectUri: "http://localhost:3000/callback",
          params: { code: "code-1" },
        }),
        { redirect: "manual" }
      ),
      {
        ...env,
        AUTH_REDIRECT_ALLOW_INSECURE_CALLBACKS: "true",
      }
    );
    expect(devInsecureOrigin.status).toBe(303);
    expect(new URL(devInsecureOrigin.headers.get("Location")!).origin).toBe(
      "http://localhost:3000"
    );

    const missing = await fetchCallback("https://worker.example.com/callback");
    expect(missing.status).toBe(400);
    expect(await missing.text()).toBe("Missing 'state' parameter");

    const malformed = await fetchCallback(
      "https://worker.example.com/callback?state=%7Bbad"
    );
    expect(malformed.status).toBe(400);
    expect(await malformed.text()).toBe("Invalid 'state' parameter");

    const invalidShape = await fetchCallback(
      "https://worker.example.com/callback?state=null"
    );
    expect(invalidShape.status).toBe(400);
    expect(await invalidShape.text()).toBe("Invalid 'state' parameter");

    const missingRedirect = await fetchCallback(
      callbackUrl({ stateExtras: { nonce: "n-1" } })
    );
    expect(missingRedirect.status).toBe(400);
    expect(await missingRedirect.text()).toBe(
      "Missing 'redirect_uri' in 'state' parameter"
    );
  });

  it("rejects invalid redirect targets", async () => {
    const malformed = await fetchCallback(
      callbackUrl({ redirectUri: "not a url" })
    );
    expect(malformed.status).toBe(400);
    expect(await malformed.text()).toBe(
      "Invalid 'redirect_uri' in 'state' parameter"
    );

    const encodedTarget = await fetchCallback(
      callbackUrl({
        redirectUri: encodeURIComponent("https://app.certless.io/callback"),
      })
    );
    expect(encodedTarget.status).toBe(400);
    expect(await encodedTarget.text()).toBe(
      "Invalid 'redirect_uri' in 'state' parameter"
    );

    const nonAllowlisted = await fetchCallback(
      callbackUrl({ redirectUri: "https://example.com/callback" })
    );
    expect(nonAllowlisted.status).toBe(403);
    expect(await nonAllowlisted.text()).toBe("Invalid redirect target");

    const apex = await fetchCallback(
      callbackUrl({ redirectUri: "https://certless.io/callback" })
    );
    expect(apex.status).toBe(403);
    expect(await apex.text()).toBe("Invalid redirect target");
  });

  it("rejects unsafe redirect URL shapes", async () => {
    const userinfo = await fetchCallback(
      callbackUrl({ redirectUri: "https://user:pass@app.certless.io/callback" })
    );
    expect(userinfo.status).toBe(403);
    expect(await userinfo.text()).toBe(
      "Userinfo not allowed in redirect URL"
    );

    const httpProduct = await fetchCallback(
      callbackUrl({ redirectUri: "http://app.certless.io/callback" })
    );
    expect(httpProduct.status).toBe(403);
    expect(await httpProduct.text()).toBe(
      "HTTPS required for non-local targets"
    );

    const customPort = await fetchCallback(
      callbackUrl({ redirectUri: "https://app.certless.io:8443/callback" })
    );
    expect(customPort.status).toBe(403);
    expect(await customPort.text()).toBe("Non-standard ports not allowed");

    const protocol = await fetchCallback(
      callbackUrl({ redirectUri: "ftp://app.certless.io/callback" })
    );
    expect(protocol.status).toBe(403);
    expect(await protocol.text()).toBe("Unsupported redirect protocol");
  });

  it("bounds state and final URL sizes", async () => {
    const hugeState = await fetchCallback(
      callbackUrl({
        redirectUri: "http://localhost:3000/callback",
        stateExtras: { filler: "x".repeat(4096) },
      })
    );
    expect(hugeState.status).toBe(400);
    expect(await hugeState.text()).toBe("State parameter too large");

    const hugeTarget = await fetchCallback(
      callbackUrl({
        redirectUri: `http://localhost:3000/callback?value=${"x".repeat(3800)}`,
        params: {
          code: "x".repeat(400),
        },
      })
    );
    expect(hugeTarget.status).toBe(400);
    expect(await hugeTarget.text()).toBe("Final URL too large");
  });
});
