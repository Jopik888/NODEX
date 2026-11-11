import test from 'node:test';
import assert from 'node:assert/strict';
import * as auth from '../auth.js';

test('auth API uses CSRF and credentialed requests across the v0.1 flow', async (t) => {
  const originalFetch = globalThis.fetch;
  const calls = [];
  let meCalls = 0;

  globalThis.fetch = async (url, options = {}) => {
    calls.push({ url: String(url), options });
    const pathname = new URL(String(url)).pathname;
    let status = 200;
    let payload = {};

    if (pathname.endsWith('/csrf-token')) {
      payload = { csrf_token: 'csrf-token-abcdefghijklmnopqrstuvwxyz123456' };
    } else if (pathname.endsWith('/auth/register')) {
      status = 201;
      payload = { user_id: 'user-1', status: 'pending_verification' };
    } else if (pathname.endsWith('/auth/verify-email')) {
      payload = { email_verified: true, status: 'active' };
    } else if (pathname.endsWith('/auth/resend-verification')) {
      status = 202;
      payload = { message: 'Verification email queued.' };
    } else if (pathname.endsWith('/auth/login')) {
      payload = {
        user: { id: 'user-1', email: 'test@example.com', status: 'active' },
        sync_room_id: 'opaque-room-identity',
        csrf_token: 'csrf-after-login-abcdefghijklmnopqrstuvwxyz',
      };
    } else if (pathname.endsWith('/auth/me')) {
      meCalls += 1;
      if (meCalls === 1) {
        status = 401;
        payload = { error: { code: 'SESSION_EXPIRED', message: 'Expired' } };
      } else {
        payload = {
          user: { id: 'user-1', email: 'test@example.com', status: 'active' },
          sync_room_id: 'opaque-room-identity',
        };
      }
    } else if (pathname.endsWith('/auth/refresh')) {
      payload = { csrf_token: 'csrf-after-refresh-abcdefghijklmnopqrstuvwxyz' };
    } else if (pathname.endsWith('/auth/logout')) {
      payload = { logged_out: true };
    }

    return new Response(JSON.stringify(payload), {
      status,
      headers: { 'Content-Type': 'application/json' },
    });
  };

  t.after(() => {
    globalThis.fetch = originalFetch;
    auth.clearClientCsrfState();
  });

  const registration = await auth.register({
    email: 'test@example.com',
    password: 'long-test-password-123',
    display_name: 'Test User',
  });
  assert.equal(registration.status, 'pending_verification');

  const resend = await auth.resendVerification('test@example.com');
  assert.equal(resend.message, 'Verification email queued.');
  const verified = await auth.verifyEmail('verification-token-abcdefghijklmnopqrstuvwxyz');
  assert.equal(verified.email_verified, true);

  const login = await auth.login({ email: 'test@example.com', password: 'long-test-password-123' });
  assert.equal(login.sync_room_id, 'opaque-room-identity');

  const restored = await auth.restoreSession();
  assert.equal(restored.sync_room_id, 'opaque-room-identity');

  const loggedOut = await auth.logout();
  assert.equal(loggedOut.logged_out, true);

  assert.equal(calls.every(({ options }) => options.credentials === 'include'), true);
  const postCalls = calls.filter(({ options }) => options.method === 'POST');
  assert.equal(postCalls.every(({ options }) => typeof options.headers['X-CSRF-Token'] === 'string'), true);
  assert.equal(calls.filter(({ url }) => new URL(url).pathname.endsWith('/auth/refresh')).length, 1);
});
