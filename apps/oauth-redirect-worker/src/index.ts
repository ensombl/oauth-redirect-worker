import {
    isLocalHostname,
    isRedirectTargetAllowed,
    parseRuntimeConfig,
} from "@ensombl/auth-config";

type WorkerEnv = Env & {
    AUTH_REDIRECT_CONFIG: string;
    AUTH_REDIRECT_ALLOW_INSECURE_CALLBACKS?: string;
};

type StatePayload = {
    redirect_uri?: unknown;
};

function textResponse(message: string, status: number): Response {
    return new Response(message, {
        status,
        headers: {
            "content-type": "text/plain; charset=utf-8",
        },
    });
}

function parseState(value: string): StatePayload | null {
    const parsed = JSON.parse(value) as unknown;
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
        return null;
    }

    return parsed as StatePayload;
}

function parseRedirectUri(value: string): URL | null {
    try {
        return new URL(value);
    } catch {
        return null;
    }
}

function isHttpUrl(url: URL): boolean {
    return url.protocol === "http:" || url.protocol === "https:";
}

function hasNonDefaultHttpsPort(url: URL): boolean {
    return url.protocol === "https:" && Boolean(url.port) && url.port !== "443";
}

function allowsInsecureCallbacks(env: WorkerEnv): boolean {
    return env.AUTH_REDIRECT_ALLOW_INSECURE_CALLBACKS === "true";
}

const handler = {
    async fetch(request, env): Promise<Response> {
        const config = parseRuntimeConfig(env.AUTH_REDIRECT_CONFIG);
        const incomingUrl = new URL(request.url);

        if (
            !allowsInsecureCallbacks(env) &&
            !isLocalHostname(incomingUrl.hostname) &&
            incomingUrl.protocol !== "https:"
        ) {
            return textResponse("HTTPS required", 400);
        }

        const stateParam = incomingUrl.searchParams.get("state");
        if (!stateParam) {
            return textResponse("Missing 'state' parameter", 400);
        }

        if (stateParam.length > config.redirects.maxStateLength) {
            return textResponse("State parameter too large", 400);
        }

        let state: StatePayload | null;
        try {
            state = parseState(stateParam);
        } catch {
            return textResponse("Invalid 'state' parameter", 400);
        }

        if (!state) {
            return textResponse("Invalid 'state' parameter", 400);
        }

        if (
            typeof state.redirect_uri !== "string" ||
            state.redirect_uri.length === 0
        ) {
            return textResponse("Missing 'redirect_uri' in 'state' parameter", 400);
        }

        const target = parseRedirectUri(state.redirect_uri);
        if (!target) {
            return textResponse("Invalid 'redirect_uri' in 'state' parameter", 400);
        }

        if (!isHttpUrl(target)) {
            return textResponse("Unsupported redirect protocol", 403);
        }

        if (target.username || target.password) {
            return textResponse("Userinfo not allowed in redirect URL", 403);
        }

        if (!isRedirectTargetAllowed(target, config)) {
            return textResponse("Invalid redirect target", 403);
        }

        const isLocalTarget = isLocalHostname(target.hostname);
        if (!isLocalTarget && target.protocol !== "https:") {
            return textResponse("HTTPS required for non-local targets", 403);
        }

        if (!isLocalTarget && hasNonDefaultHttpsPort(target)) {
            return textResponse("Non-standard ports not allowed", 403);
        }

        target.hash = "";

        for (const param of config.redirects.stripTargetParams) {
            target.searchParams.delete(param);
        }

        const forwardedParams = new Set(config.redirects.forwardedCallbackParams);
        for (const [key, value] of incomingUrl.searchParams.entries()) {
            if (forwardedParams.has(key)) {
                target.searchParams.set(key, value);
            }
        }

        const finalUrl = target.toString();
        if (finalUrl.length > config.redirects.maxFinalUrlLength) {
            return textResponse("Final URL too large", 400);
        }

        return Response.redirect(finalUrl, 303);
    },
} satisfies ExportedHandler<WorkerEnv>;

export default handler;
