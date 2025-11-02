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

        // Check if this is the oauth-redirect.coda.to route
        const isProductionOAuthRedirectRoute = incomingUrl.hostname.match(
            "oauth-redirect.coda.to"
        );

        // Enforce HTTPS for oauth-redirect.coda.to
        if (
            isProductionOAuthRedirectRoute &&
            incomingUrl.protocol !== "https:"
        ) {
            return new Response("HTTPS required for oauth-redirect.coda.to", {
                status: 400,
            });
        }

        const stateParam = params.get("state");

        // Bound sizes: cap state parameter length
        if (stateParam && stateParam.length > 4096) {
            return new Response("State parameter too large", { status: 400 });
        }

        let stateParamObj: Record<string, string> = {};
        try {
            stateParamObj = JSON.parse(stateParam || "{}");
        } catch {
            return new Response("Invalid 'state' parameter", { status: 400 });
        }

        const targetEncoded = stateParamObj?.redirect_uri;
        if (!targetEncoded) {
            return new Response("Missing 'redirect_uri' in 'state' parameter", {
                status: 400,
            });
        }

        let target: URL;
        try {
            target = new URL(decodeURIComponent(targetEncoded));
        } catch {
            return new Response("Invalid 'redirect_uri' in 'state' parameter", {
                status: 400,
            });
        }

        // Security checks for target URL
        // 1. Block userinfo (username:password)
        if (target.username || target.password) {
            return new Response("Userinfo not allowed in redirect URL", {
                status: 403,
            });
        }

        // 2. Block non-standard ports (only allow default HTTPS port 443 when https)
        if (
            target.protocol === "https:" &&
            target.port &&
            target.port !== "443"
        ) {
            return new Response("Non-standard ports not allowed", {
                status: 403,
            });
        }

        // 3. Drop fragments to avoid smuggling data
        target.hash = "";

        // 4. Strip redirect-like parameters from target (defense-in-depth)
        const REDIRECT_PARAMS = new Set([
            "redirect",
            "redirect_uri",
            "return_to",
            "returnTo",
            "next",
            "url",
            "destination",
            "continue",
            "goto",
            "target",
            "forward",
            "callback",
        ]);
        for (const param of REDIRECT_PARAMS) {
            target.searchParams.delete(param);
        }

        // Forward only a minimal allowlist of OAuth params
        const OAUTH_ALLOWLIST = new Set([
            "code",
            "state",
            "scope",
            "iss",
            "session_state",
            "error",
            "error_description",
        ]);
        for (const [key, value] of params.entries()) {
            if (OAUTH_ALLOWLIST.has(key)) {
                target.searchParams.set(key, value);
            }
        }

        // ------------ Unified validation logic ------------
        // Check if target is localhost
        const isLocal =
            target.hostname.match("localhost") ||
            target.hostname.endsWith(".localhost") ||
            target.hostname.startsWith("127.");

        // Check if target is an allowed domain
        const isAllowedDomain =
            target.hostname === "app.coda.to" ||
            target.hostname === "app.preview.coda.to" ||
            target.hostname === "preview.coda.to" ||
            target.hostname.match("app.staging.coda.to") ||
            target.hostname.match("preview.app.coda.to") ||
            target.hostname.endsWith(".vercel.app");

        // Validate target domain
        if (!isLocal && !isAllowedDomain) {
            return new Response("Invalid redirect target", { status: 403 });
        }

        // For non-local targets, enforce HTTPS and default port
        if (!isLocal) {
            if (target.protocol !== "https:") {
                return new Response("HTTPS required for non-local targets", {
                    status: 403,
                });
            }
            if (target.port && target.port !== "443") {
                return new Response("Non-standard ports not allowed", {
                    status: 403,
                });
            }
        }
        // ------------ End of validation logic ------------

        // Final URL length check
        const finalUrl = target.toString();
        if (finalUrl.length > 4096) {
            return new Response("Final URL too large", { status: 400 });
        }

        return Response.redirect(finalUrl, 303);
    },
} satisfies ExportedHandler<Env>;
