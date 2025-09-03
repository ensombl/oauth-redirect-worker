/**
 * Welcome to Cloudflare Workers! This is your first worker.
 *
 * - Run `npm run dev` in your terminal to start a development server
 * - Open a browser tab at http://localhost:8787/ to see your worker in action
 * - Run `npm run deploy` to publish your worker
 *
 * Bind resources to your worker in `wrangler.jsonc`. After adding bindings, a type definition for the
 * `Env` object can be regenerated with `npm run cf-typegen`.
 *
 * Learn more at https://developers.cloudflare.com/workers/
 */

export default {
  async fetch(request, env, ctx): Promise<Response> {
    const incomingUrl = new URL(request.url);
    const params = incomingUrl.searchParams;

    const stateParam = params.get("state");
    let stateParamObj: Record<string, string> = {};
    try {
      stateParamObj = JSON.parse(stateParam || "{}");
    } catch {
      return new Response("Invalid 'state' parameter", { status: 400 });
    }

    const targetEncoded = stateParamObj?.redirect_uri;
    if (!targetEncoded) {
      return new Response("Missing 'redirect_uri' in 'state' parameter", { status: 400 });
    }

    let target: URL;
    try {
      target = new URL(decodeURIComponent(targetEncoded));
    } catch {
      return new Response("Invalid 'redirect_uri' in 'state' parameter", { status: 400 });
    }

    for (const [key, value] of params.entries()) {
      target.searchParams.set(key, value);
    }

    if (
      !target.hostname.endsWith("localhost") &&
      !target.hostname.startsWith("127.") &&
      !target.hostname.match("app.staging.coda.to") &&
      !target.hostname.match("preview.app.coda.to") &&
      !target.hostname.endsWith("vercel.app")
    ) {
      return new Response("Invalid redirect target", { status: 403 });
    }

    return Response.redirect(target.toString(), 302);
  },
} satisfies ExportedHandler<Env>;
