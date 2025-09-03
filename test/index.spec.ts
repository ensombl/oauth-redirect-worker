import { env, createExecutionContext, waitOnExecutionContext } from 'cloudflare:test';
import { describe, it, expect } from 'vitest';
import worker from '../src/index';

// Helper to create a Request object with the correct type for Cloudflare Workers
const IncomingRequest = Request<unknown, IncomingRequestCfProperties>;

const WORKER_BASE_URL = 'http://worker.example.com'; // Consistent base for testing originalUrl

describe('OAuth Trampoline Worker', () => {
  it('Test Case 1: Basic Valid Redirect (code & state)', async () => {
    const targetActual = 'http://localhost:3000/auth/tiktok';
    const targetEncoded = encodeURIComponent(targetActual);
    const request = new IncomingRequest(
      `${WORKER_BASE_URL}/callback?url=${targetEncoded}&code=testcode123&state=teststate789`
    );
    const ctx = createExecutionContext();
    const response = await worker.fetch(request, env, ctx);
    await waitOnExecutionContext(ctx);

    expect(response.status).toBe(302);
    const location = response.headers.get('Location');
    expect(location).toBeDefined();

    const finalUrl = new URL(location!);
    expect(finalUrl.origin + finalUrl.pathname).toBe(targetActual);
    expect(finalUrl.searchParams.get('code')).toBe('testcode123');
    expect(finalUrl.searchParams.get('state')).toBe('teststate789');

    const expectedOriginalWorkerUrl = `${WORKER_BASE_URL}/callback?url=${targetEncoded}`;
    expect(finalUrl.searchParams.get('originalUrl')!).toBe(expectedOriginalWorkerUrl);
  });

  it('Test Case 2: Valid Redirect with Pre-existing Query Params in Target URL', async () => {
    const targetActual = 'http://localhost:3000/auth/tiktok?customParam=abc';
    const targetEncoded = encodeURIComponent(targetActual);
    const request = new IncomingRequest(
      `${WORKER_BASE_URL}/callback?url=${targetEncoded}&code=testcode456`
    );
    const ctx = createExecutionContext();
    const response = await worker.fetch(request, env, ctx);
    await waitOnExecutionContext(ctx);

    expect(response.status).toBe(302);
    const location = response.headers.get('Location');
    expect(location).toBeDefined();

    const finalUrl = new URL(location!);
    expect(finalUrl.origin + finalUrl.pathname).toBe('http://localhost:3000/auth/tiktok');
    expect(finalUrl.searchParams.get('customParam')).toBe('abc');
    expect(finalUrl.searchParams.get('code')).toBe('testcode456');

    const expectedOriginalWorkerUrl = `${WORKER_BASE_URL}/callback?url=${targetEncoded}`;
    expect(finalUrl.searchParams.get('originalUrl')!).toBe(expectedOriginalWorkerUrl);
  });

  it('Test Case 3: Valid Redirect to 127.0.0.1', async () => {
    const targetActual = 'http://127.0.0.1:8080/path';
    const targetEncoded = encodeURIComponent(targetActual);
    const request = new IncomingRequest(
      `${WORKER_BASE_URL}/callback?url=${targetEncoded}&code=testcode789`
    );
    const ctx = createExecutionContext();
    const response = await worker.fetch(request, env, ctx);
    await waitOnExecutionContext(ctx);

    expect(response.status).toBe(302);
    const location = response.headers.get('Location');
    expect(location).toBeDefined();

    const finalUrl = new URL(location!);
    expect(finalUrl.origin + finalUrl.pathname).toBe(targetActual);
    expect(finalUrl.searchParams.get('code')).toBe('testcode789');

    const expectedOriginalWorkerUrl = `${WORKER_BASE_URL}/callback?url=${targetEncoded}`;
    expect(finalUrl.searchParams.get('originalUrl')!).toBe(expectedOriginalWorkerUrl);
  });

  it('Test Case 4: Target URL with a Fragment', async () => {
    const targetActualBase = 'http://localhost:3000/callback';
    const targetActualWithFragment = `${targetActualBase}#section`;
    const targetEncoded = encodeURIComponent(targetActualWithFragment);
    const request = new IncomingRequest(
      `${WORKER_BASE_URL}/callback?url=${targetEncoded}&code=testcode`
    );
    const ctx = createExecutionContext();
    const response = await worker.fetch(request, env, ctx);
    await waitOnExecutionContext(ctx);

    expect(response.status).toBe(302);
    const location = response.headers.get('Location');
    expect(location).toBeDefined();

    const finalUrl = new URL(location!);
    expect(finalUrl.origin + finalUrl.pathname).toBe(targetActualBase);
    expect(finalUrl.hash).toBe('#section');
    expect(finalUrl.searchParams.get('code')).toBe('testcode');

    const expectedOriginalWorkerUrl = `${WORKER_BASE_URL}/callback?url=${targetEncoded}`;
    expect(finalUrl.searchParams.get('originalUrl')!).toBe(expectedOriginalWorkerUrl);
  });

  it('Test Case 5: Missing "url" Parameter', async () => {
    const request = new IncomingRequest(`${WORKER_BASE_URL}/callback?code=testcode`);
    const ctx = createExecutionContext();
    const response = await worker.fetch(request, env, ctx);
    await waitOnExecutionContext(ctx);

    expect(response.status).toBe(400);
    expect(await response.text()).toBe("Missing 'url' parameter");
  });

  it('Test Case 6: Invalid (Malformed) "url" Parameter', async () => {
    const request = new IncomingRequest(`${WORKER_BASE_URL}/callback?url=this_is_not_a_url`);
    const ctx = createExecutionContext();
    const response = await worker.fetch(request, env, ctx);
    await waitOnExecutionContext(ctx);

    expect(response.status).toBe(400);
    expect(await response.text()).toBe("Invalid 'url' parameter");
  });

  it('Test Case 7: Empty "url" Parameter', async () => {
    const request = new IncomingRequest(`${WORKER_BASE_URL}/callback?url=`);
    const ctx = createExecutionContext();
    const response = await worker.fetch(request, env, ctx);
    await waitOnExecutionContext(ctx);

    expect(response.status).toBe(400);
    expect(await response.text()).toBe("Missing 'url' parameter");
  });

  it('Test Case 8: Redirect to Non-Allowlisted Hostname', async () => {
    const targetActual = 'http://example.com/callback';
    const targetEncoded = encodeURIComponent(targetActual);
    const request = new IncomingRequest(
      `${WORKER_BASE_URL}/callback?url=${targetEncoded}&code=testcode`
    );
    const ctx = createExecutionContext();
    const response = await worker.fetch(request, env, ctx);
    await waitOnExecutionContext(ctx);

    expect(response.status).toBe(403);
    expect(await response.text()).toBe('Invalid redirect target');
  });

  it('Test Case 9: No Additional OAuth Parameters', async () => {
    const targetActual = 'http://localhost:3000/justurl';
    const targetEncoded = encodeURIComponent(targetActual);
    const request = new IncomingRequest(`${WORKER_BASE_URL}/callback?url=${targetEncoded}`);
    const ctx = createExecutionContext();
    const response = await worker.fetch(request, env, ctx);
    await waitOnExecutionContext(ctx);

    expect(response.status).toBe(302);
    const location = response.headers.get('Location');
    expect(location).toBeDefined();

    const finalUrl = new URL(location!);
    expect(finalUrl.origin + finalUrl.pathname).toBe(targetActual);
    expect(finalUrl.searchParams.has('code')).toBe(false); // Ensure no accidental code param

    const expectedOriginalWorkerUrl = `${WORKER_BASE_URL}/callback?url=${targetEncoded}`;
    expect(finalUrl.searchParams.get('originalUrl')!).toBe(expectedOriginalWorkerUrl);
  });
});
