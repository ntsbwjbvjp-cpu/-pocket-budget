import { buildPushHTTPRequest } from '@pushforge/builder';

const APP_ORIGIN = 'https://ntsbwjbvjp-cpu.github.io';
const APP_URL = 'https://ntsbwjbvjp-cpu.github.io/-pocket-budget/';

export default {
  async fetch(request, env) {
    const origin = request.headers.get('Origin');
    const cors = {
      'Access-Control-Allow-Origin': origin === APP_ORIGIN ? APP_ORIGIN : APP_ORIGIN,
      'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-Device-ID',
      'Access-Control-Allow-Methods': 'GET, POST, DELETE, OPTIONS',
      'Vary': 'Origin'
    };
    if (request.method === 'OPTIONS') return new Response(null, { status: 204, headers: cors });
    if (origin && origin !== APP_ORIGIN) return json({ error: 'Origin not allowed' }, 403, cors);
    const url = new URL(request.url);
    if (url.pathname === '/health') return json({ ok: true, service: 'Pocket Budget notifications' }, 200, cors);
    const id = env.REMINDERS.idFromName('pocket-budget');
    const response = await env.REMINDERS.get(id).fetch(request);
    const headers = new Headers(response.headers);
    Object.entries(cors).forEach(([key, value]) => headers.set(key, value));
    return new Response(response.body, { status: response.status, headers });
  }
};

export class ReminderHub {
  constructor(ctx, env) {
    this.ctx = ctx;
    this.env = env;
  }

  async fetch(request) {
    await this.ensureSetup();
    const url = new URL(request.url);
    try {
      if (request.method === 'GET' && url.pathname === '/api/public-key') {
        const keys = await this.ctx.storage.get('vapid');
        return json({ publicKey: keys.publicKey });
      }
      if (request.method === 'POST' && url.pathname === '/api/subscribe') return this.subscribe(request);
      if (request.method === 'POST' && url.pathname === '/api/reminders') return this.saveReminders(request);
      if (request.method === 'POST' && url.pathname === '/api/test') return this.testNotification(request);
      if (request.method === 'DELETE' && url.pathname === '/api/subscribe') return this.unsubscribe(request);
      return json({ error: 'Not found' }, 404);
    } catch (error) {
      console.error(error);
      return json({ error: 'Unable to complete request' }, 500);
    }
  }

  async ensureSetup() {
    if (!await this.ctx.storage.get('vapid')) {
      const keyPair = await crypto.subtle.generateKey(
        { name: 'ECDSA', namedCurve: 'P-256' },
        true,
        ['sign', 'verify']
      );
      const privateJWK = await crypto.subtle.exportKey('jwk', keyPair.privateKey);
      const publicJWK = await crypto.subtle.exportKey('jwk', keyPair.publicKey);
      const publicKey = bytesToBase64Url(concatBytes(
        new Uint8Array([4]),
        base64UrlToBytes(publicJWK.x),
        base64UrlToBytes(publicJWK.y)
      ));
      await this.ctx.storage.put('vapid', { privateJWK, publicKey });
    }
    if (!await this.ctx.storage.getAlarm()) await this.ctx.storage.setAlarm(Date.now() + 60 * 60 * 1000);
  }

  async subscribe(request) {
    const body = await safeJson(request);
    if (!validSubscription(body.subscription)) return json({ error: 'Invalid subscription' }, 400);
    let deviceId = cleanId(body.deviceId);
    const suppliedToken = typeof body.token === 'string' ? body.token : '';
    let device = deviceId ? await this.ctx.storage.get(`device:${deviceId}`) : null;
    if (device && suppliedToken && await tokenMatches(suppliedToken, device.tokenHash)) {
      device.subscription = body.subscription;
      device.updatedAt = new Date().toISOString();
      await this.ctx.storage.put(`device:${deviceId}`, device);
      return json({ deviceId, token: suppliedToken, updated: true });
    }
    deviceId = crypto.randomUUID();
    const token = randomToken();
    device = {
      id: deviceId,
      tokenHash: await hashToken(token),
      subscription: body.subscription,
      reminders: [],
      lastSent: {},
      createdAt: new Date().toISOString()
    };
    await this.ctx.storage.put(`device:${deviceId}`, device);
    return json({ deviceId, token, updated: false });
  }

  async saveReminders(request) {
    const auth = await this.authorise(request);
    if (!auth) return json({ error: 'Unauthorised' }, 401);
    const body = await safeJson(request);
    if (!Array.isArray(body.reminders) || body.reminders.length > 50) return json({ error: 'Invalid reminders' }, 400);
    auth.device.reminders = body.reminders.map(sanitiseReminder).filter(Boolean);
    auth.device.updatedAt = new Date().toISOString();
    await this.ctx.storage.put(auth.key, auth.device);
    return json({ saved: auth.device.reminders.length });
  }

  async testNotification(request) {
    const auth = await this.authorise(request);
    if (!auth) return json({ error: 'Unauthorised' }, 401);
    const result = await this.send(auth.device.subscription, {
      title: 'Pocket Budget',
      body: 'Notifications are working. Your bill reminders will appear here.',
      url: APP_URL,
      tag: 'pocket-budget-test'
    });
    return json({ sent: result.ok }, result.ok ? 200 : 502);
  }

  async unsubscribe(request) {
    const auth = await this.authorise(request);
    if (!auth) return json({ error: 'Unauthorised' }, 401);
    await this.ctx.storage.delete(auth.key);
    return json({ removed: true });
  }

  async authorise(request) {
    const deviceId = cleanId(request.headers.get('X-Device-ID'));
    const token = (request.headers.get('Authorization') || '').replace(/^Bearer\s+/i, '');
    if (!deviceId || !token) return null;
    const key = `device:${deviceId}`;
    const device = await this.ctx.storage.get(key);
    if (!device || !await tokenMatches(token, device.tokenHash)) return null;
    return { key, device };
  }

  async alarm() {
    try {
      const now = brisbaneNow();
      if (now.hour !== 9) return;
      const devices = await this.ctx.storage.list({ prefix: 'device:' });
      for (const [key, device] of devices) {
        let changed = false;
        for (const reminder of device.reminders || []) {
          if (!reminder.active) continue;
          const due = nextOccurrence(reminder.nextDue, reminder.period, now.date);
          if (!due) continue;
          const alertDate = shiftDays(due, -reminder.remindDays);
          const sentKey = `${reminder.id}:${alertDate}`;
          if (alertDate !== now.date || device.lastSent?.[reminder.id] === sentKey) continue;
          const timing = reminder.remindDays === 0 ? 'is due today' : reminder.remindDays === 1 ? 'is due tomorrow' : `is due in ${reminder.remindDays} days`;
          const result = await this.send(device.subscription, {
            title: 'Pocket Budget',
            body: `${reminder.label} ${timing}.`,
            url: APP_URL,
            tag: `bill-${reminder.id}`
          });
          if (result.ok) {
            device.lastSent = device.lastSent || {};
            device.lastSent[reminder.id] = sentKey;
            changed = true;
          } else if (result.gone) {
            await this.ctx.storage.delete(key);
            changed = false;
            break;
          }
        }
        if (changed) await this.ctx.storage.put(key, device);
      }
    } catch (error) {
      console.error('Reminder alarm failed', error);
    } finally {
      await this.ctx.storage.setAlarm(Date.now() + 60 * 60 * 1000);
    }
  }

  async send(subscription, payload) {
    const keys = await this.ctx.storage.get('vapid');
    const push = await buildPushHTTPRequest({
      privateJWK: keys.privateJWK,
      subscription,
      message: {
        payload,
        adminContact: APP_URL,
        options: { ttl: 86400, urgency: 'normal', topic: payload.tag }
      }
    });
    const response = await fetch(push.endpoint, { method: 'POST', headers: push.headers, body: push.body });
    return { ok: response.ok, gone: response.status === 404 || response.status === 410, status: response.status };
  }
}

function sanitiseReminder(value) {
  if (!value || typeof value !== 'object') return null;
  const id = cleanId(value.id) || crypto.randomUUID();
  const label = String(value.label || 'Bill').trim().slice(0, 80);
  const nextDue = /^\d{4}-\d{2}-\d{2}$/.test(value.nextDue || '') ? value.nextDue : '';
  const period = ['Weekly', 'Fortnightly', 'Monthly', 'Yearly'].includes(value.period) ? value.period : 'Monthly';
  const remindDays = [0, 1, 3, 7].includes(Number(value.remindDays)) ? Number(value.remindDays) : 1;
  if (!nextDue) return null;
  return { id, label, nextDue, period, remindDays, active: value.active !== false };
}

function validSubscription(value) {
  return value && typeof value.endpoint === 'string' && value.endpoint.startsWith('https://') && value.keys && typeof value.keys.p256dh === 'string' && typeof value.keys.auth === 'string';
}

function cleanId(value) {
  const id = typeof value === 'string' ? value : '';
  return /^[a-zA-Z0-9-]{1,80}$/.test(id) ? id : '';
}

async function safeJson(request) {
  try { return await request.json(); } catch { return {}; }
}

async function hashToken(token) {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(token));
  return bytesToBase64Url(new Uint8Array(digest));
}

async function tokenMatches(token, expected) {
  return await hashToken(token) === expected;
}

function randomToken() {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  return bytesToBase64Url(bytes);
}

function brisbaneNow() {
  const parts = Object.fromEntries(new Intl.DateTimeFormat('en-CA', {
    timeZone: 'Australia/Brisbane', year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', hourCycle: 'h23'
  }).formatToParts(new Date()).filter(part => part.type !== 'literal').map(part => [part.type, part.value]));
  return { date: `${parts.year}-${parts.month}-${parts.day}`, hour: Number(parts.hour) };
}

function nextOccurrence(base, period, today) {
  let date = parseDate(base);
  const target = parseDate(today);
  if (!date || !target) return null;
  let guard = 0;
  while (date < target && guard++ < 600) date = advance(date, period);
  return dateString(date);
}

function advance(date, period) {
  const next = new Date(date);
  if (period === 'Weekly') next.setUTCDate(next.getUTCDate() + 7);
  else if (period === 'Fortnightly') next.setUTCDate(next.getUTCDate() + 14);
  else if (period === 'Yearly') next.setUTCFullYear(next.getUTCFullYear() + 1);
  else next.setUTCMonth(next.getUTCMonth() + 1);
  return next;
}

function shiftDays(date, days) {
  const value = parseDate(date);
  value.setUTCDate(value.getUTCDate() + days);
  return dateString(value);
}

function parseDate(value) {
  if (!/^\d{4}-\d{2}-\d{2}$/.test(value || '')) return null;
  const [year, month, day] = value.split('-').map(Number);
  return new Date(Date.UTC(year, month - 1, day, 12));
}

function dateString(date) {
  return `${date.getUTCFullYear()}-${String(date.getUTCMonth() + 1).padStart(2, '0')}-${String(date.getUTCDate()).padStart(2, '0')}`;
}

function base64UrlToBytes(value) {
  const base64 = value.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - value.length % 4) % 4);
  const binary = atob(base64);
  return Uint8Array.from(binary, char => char.charCodeAt(0));
}

function bytesToBase64Url(bytes) {
  let binary = '';
  bytes.forEach(byte => binary += String.fromCharCode(byte));
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

function concatBytes(...arrays) {
  const output = new Uint8Array(arrays.reduce((sum, value) => sum + value.length, 0));
  let offset = 0;
  arrays.forEach(value => { output.set(value, offset); offset += value.length; });
  return output;
}

function json(value, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(value), {
    status,
    headers: { 'Content-Type': 'application/json; charset=utf-8', ...extraHeaders }
  });
}
