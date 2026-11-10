import { createHmac, createHash, createCipheriv, createDecipheriv, randomBytes } from 'node:crypto';
import { readFileSync, writeFileSync, existsSync, unlinkSync } from 'node:fs';

const GTC_BASE = 'https://pbssrv-centralevents.com';
const VFK_BASE = 'https://api.verifykit.com';
const HMAC_KEY = '31426764382a642f3a6665497235466f3d236d5d785b722b4c657457442a495b494524324866782a2364292478587a78662d7a7b7578593f71703e2b7e365762';
const VFK_HMAC_KEY = '3452235d713252604a35562d325f765238695738485863672a705e6841544d3c7e6e45463028266f372b544e596f3829236b392825262e534a7e774f37653932';
const VFK_CLIENT_KEY = 'bhvbd7ced119dc6ad6a0b35bd3cf836555d6f71930d9e5a405f32105c790d';
const VFK_FINAL_KEY = 'bd48d8c25293cfb537619cc93ae3d6e372eb2ddfffff4ab0eb000777144c7bfa';
const BUNDLE_ID = 'app.source.getcontact';
const DH_P = 900719898367n;
const DH_G = 7n;
const APP_VERSION = '8.4.0';
const ANDROID_OS = 'android 9';
const LANG = 'en_US';
const COUNTRY = 'id';
const SESSION_FILE = '/root/Scrape/getcontact_session.json';
const PENDING_FILE = '/root/Scrape/getcontact_pending.json';

function modPow(base, exp, mod) {
  let res = 1n;
  base = base % mod;
  while (exp > 0n) {
    if (exp % 2n === 1n) res = (res * base) % mod;
    base = (base * base) % mod;
    exp = exp / 2n;
  }
  return res;
}

function dhKeypair() {
  const priv = BigInt(Math.floor(Math.random() * 99000000) + 1000000);
  const pub = modPow(DH_G, priv, DH_P);
  return { priv, pub: Number(pub) };
}

function dhFinalKey(priv, serverPub) {
  const shared = modPow(BigInt(serverPub), priv, DH_P);
  return createHash('sha256').update(shared.toString()).digest('hex');
}

function sig(ts, message, keyHex) {
  return createHmac('sha256', Buffer.from(keyHex, 'hex'))
    .update(`${ts}-${message}`)
    .digest('base64');
}

function encrypt(text, keyHex) {
  const cipher = createCipheriv('aes-256-ecb', Buffer.from(keyHex, 'hex'), null);
  return Buffer.concat([cipher.update(text, 'utf8'), cipher.final()]).toString('base64');
}

function decrypt(b64, keyHex) {
  const decipher = createDecipheriv('aes-256-ecb', Buffer.from(keyHex, 'hex'), null);
  return Buffer.concat([decipher.update(Buffer.from(b64, 'base64')), decipher.final()]).toString('utf8');
}

export function normalizePhone(raw) {
  if (!raw || typeof raw !== 'string') throw new Error('Phone number is required');
  const p = raw.trim().replace(/[^\d+]/g, '');
  if (p.startsWith('+')) return p;
  if (p.startsWith('0')) return `+62${p.slice(1)}`;
  if (p.startsWith('62')) return `+${p}`;
  return `+${p}`;
}

export function saveSession(creds, filePath = SESSION_FILE) {
  writeFileSync(filePath, JSON.stringify(creds, null, 2), 'utf-8');
}

export function loadSession(filePath = SESSION_FILE) {
  if (!existsSync(filePath)) return null;
  try {
    return JSON.parse(readFileSync(filePath, 'utf-8'));
  } catch {
    return null;
  }
}

async function vfkCall(endpoint, payload, deviceId) {
  const raw = JSON.stringify(payload);
  const ts = String(Date.now());
  const signature = sig(ts, raw, VFK_HMAC_KEY);

  const res = await fetch(`${VFK_BASE}${endpoint}`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-VFK-Client-Device-Id': deviceId,
      'X-VFK-Client-Key': VFK_CLIENT_KEY,
      'X-VFK-Sdk-Version': '0.11.4',
      'X-VFK-Os': 'android 9.0',
      'X-VFK-App-Version': '8.16.0',
      'X-VFK-Encrypted': '1',
      'X-VFK-Lang': 'in_ID',
      'X-VFK-Req-Timestamp': ts,
      'X-VFK-Req-Signature': signature
    },
    body: JSON.stringify({ data: encrypt(raw, VFK_FINAL_KEY) })
  });

  const json = await res.json();
  if (json.data) {
    try {
      return { status: res.status, data: JSON.parse(decrypt(json.data, VFK_FINAL_KEY)) };
    } catch {}
  }
  return { status: res.status, data: json };
}

async function gtcCall(endpoint, payload, { token, finalKey, clientDeviceId }) {
  const raw = JSON.stringify(payload);
  const ts = String(Date.now());
  const signature = sig(ts, raw, HMAC_KEY);

  const res = await fetch(`${GTC_BASE}${endpoint}`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'x-os': ANDROID_OS,
      'x-app-version': APP_VERSION,
      'x-client-device-id': clientDeviceId,
      'x-lang': LANG,
      'x-req-timestamp': ts,
      'x-country-code': COUNTRY,
      'x-encrypted': '1',
      'x-req-signature': signature,
      'x-token': token,
      'User-Agent': 'okhttp/4.12.0'
    },
    body: JSON.stringify({ data: encrypt(raw, finalKey) })
  });

  const json = await res.json();
  if (json.data) {
    try {
      return { status: res.status, data: JSON.parse(decrypt(json.data, finalKey)) };
    } catch {}
  }
  return { status: res.status, data: json };
}

export async function initAuth(phoneNumber, options = {}) {
  const phone = normalizePhone(phoneNumber);
  const deviceId = options.clientDeviceId || randomBytes(8).toString('hex');
  const { priv, pub } = dhKeypair();
  const ts = String(Date.now());

  const regBody = {
    carrierCountryCode: '510',
    carrierName: 'Indosat Ooredoo',
    carrierNetworkCode: '01',
    countryCode: COUNTRY,
    deepLink: null,
    deviceName: 'SM-G977N',
    deviceType: 'Android',
    email: null,
    notificationToken: '',
    oldToken: null,
    peerKey: pub,
    timeZone: 'Asia/Bangkok',
    token: ''
  };

  const raw = JSON.stringify(regBody);
  const signature = sig(ts, raw, HMAC_KEY);

  const res = await fetch(`${GTC_BASE}/v2.8/register`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'x-os': ANDROID_OS,
      'x-app-version': APP_VERSION,
      'x-client-device-id': deviceId,
      'x-lang': LANG,
      'x-req-timestamp': ts,
      'x-country-code': COUNTRY,
      'x-encrypted': '0',
      'x-req-signature': signature,
      'User-Agent': 'okhttp/4.12.0'
    },
    body: raw
  });

  const regJson = await res.json();
  if (res.status !== 201 || !regJson.result?.token || !regJson.result?.serverKey) {
    throw new Error(regJson.meta?.errorMessage || `Registration failed: HTTP ${res.status}`);
  }

  const token = regJson.result.token;
  const finalKey = dhFinalKey(priv, regJson.result.serverKey);
  const common = { token, finalKey, clientDeviceId: deviceId };

  const base = {
    carrierCountryCode: '510',
    carrierName: 'Indosat Ooredoo',
    carrierNetworkCode: '01',
    countryCode: COUNTRY,
    deviceName: 'SM-G977N',
    notificationToken: '',
    timeZone: 'Asia/Bangkok',
    token
  };

  await gtcCall('/v2.8/init-basic', base, common);
  await gtcCall('/v2.8/ad-settings', { source: 'init', token }, common);
  await gtcCall('/v2.8/init-intro', { ...base, hasRouting: false }, common);
  await gtcCall('/v2.8/country', { countryCode: 'ID', token }, common);
  await gtcCall('/v2.8/validation-start', { app: 'verifykit', countryCode: COUNTRY, notificationToken: '', token }, common);

  await vfkCall('/v2.0/init', {
    isCallPermissionGranted: true,
    countryCode: 'ID',
    deviceName: 'SM-G977N',
    installedApps: '{"whatsapp":0,"telegram":0,"viber":0}',
    outsideCountryCode: 'ID',
    outsidePhoneNumber: phone,
    timezone: 'Asia/Bangkok',
    bundleId: BUNDLE_ID
  }, deviceId);

  await vfkCall('/v2.0/country', { countryCode: 'ID', bundleId: BUNDLE_ID }, deviceId);

  const startRes = await vfkCall('/v2.0/start', {
    countryCode: 'ID',
    mcc: '510',
    mnc: '01',
    phoneNumber: phone,
    app: 'whatsapp',
    bundleId: BUNDLE_ID
  }, deviceId);

  const deeplink = startRes.data?.result?.deeplink;
  const reference = startRes.data?.result?.reference;

  if (!deeplink || !reference) {
    throw new Error(startRes.data?.meta?.errorMessage || 'Gagal memulai sesi VerifyKit');
  }

  const session = {
    phoneNumber: phone,
    clientDeviceId: deviceId,
    token,
    finalKey,
    reference,
    deeplink,
    message: 'Buka tautan deeplink WhatsApp dan kirim pesan verifikasi. Setelah centang dua, panggil checkAuth().'
  };

  try {
    writeFileSync(PENDING_FILE, JSON.stringify(session, null, 2), 'utf-8');
  } catch {}

  return session;
}

export async function checkAuth(input = null, save = true) {
  let session = null;
  if (input && typeof input === 'object' && input.reference && input.token) {
    session = input;
  } else if (existsSync(PENDING_FILE)) {
    try {
      session = JSON.parse(readFileSync(PENDING_FILE, 'utf-8'));
    } catch {}
  }

  if (!session || !session.reference || !session.token) {
    throw new Error('Sesi tidak ditemukan. Jalankan initAuth() terlebih dahulu.');
  }

  const checkRes = await vfkCall('/v2.0/check', {
    reference: session.reference,
    bundleId: BUNDLE_ID
  }, session.clientDeviceId);

  const sessionId = checkRes.data?.result?.sessionId;
  if (!sessionId) {
    return {
      verified: false,
      message: 'Belum terverifikasi. Pastikan pesan WhatsApp sudah terkirim centang dua.'
    };
  }

  const resultRes = await gtcCall('/v2.8/verifykit-result', {
    sessionId,
    token: session.token
  }, session);

  const validationDate = resultRes.data?.result?.validationDate;
  if (!validationDate) {
    throw new Error(resultRes.data?.meta?.errorMessage || 'Gagal mengonfirmasi hasil VerifyKit');
  }

  const credentials = {
    phoneNumber: session.phoneNumber,
    clientDeviceId: session.clientDeviceId,
    token: session.token,
    finalKey: session.finalKey,
    validationDate
  };

  if (save) saveSession(credentials);

  try {
    unlinkSync(PENDING_FILE);
  } catch {}

  return {
    verified: true,
    credentials,
    message: 'Nomor berhasil diverifikasi dan kredensial telah disimpan otomatis!'
  };
}

function resolveCreds(customCreds) {
  if (customCreds && customCreds.token && customCreds.finalKey && customCreds.clientDeviceId) {
    return customCreds;
  }
  const saved = loadSession();
  if (saved && saved.token && saved.finalKey && saved.clientDeviceId) {
    return saved;
  }
  if (process.env.GTC_TOKEN && process.env.GTC_FINAL_KEY && process.env.GTC_DEVICE_ID) {
    return {
      token: process.env.GTC_TOKEN,
      finalKey: process.env.GTC_FINAL_KEY,
      clientDeviceId: process.env.GTC_DEVICE_ID
    };
  }
  throw new Error('Kredensial belum tersedia. Jalankan initAuth() dan checkAuth(), atau sediakan token terverifikasi.');
}

export async function search(phoneNumber, customCreds = null) {
  const creds = resolveCreds(customCreds);
  const phone = normalizePhone(phoneNumber);
  const res = await gtcCall('/v2.8/search', {
    countryCode: COUNTRY,
    phoneNumber: phone,
    source: 'search',
    token: creds.token
  }, creds);

  if (res.data?.meta && res.data.meta.httpStatusCode !== 200) {
    const msg = res.data.meta.errorMessage || `HTTP error ${res.status}`;
    const code = res.data.meta.errorCode || res.status;
    throw new Error(`[Getcontact ${code}] ${msg}`);
  }

  const d = res.data?.result || {};
  const profile = d.profile || {};
  return {
    phone,
    name: profile.name || '',
    surname: profile.surname || '',
    displayName: profile.displayName || '',
    email: profile.email || '',
    tagCount: profile.tagCount || 0,
    tags: (d.tags || []).map((t) => ({
      tag: t.tag,
      count: t.count || 1
    }))
  };
}

export async function getTags(phoneNumber, customCreds = null) {
  const creds = resolveCreds(customCreds);
  const phone = normalizePhone(phoneNumber);
  const res = await gtcCall('/v2.8/number-detail', {
    countryCode: COUNTRY,
    phoneNumber: phone,
    source: 'profile',
    token: creds.token
  }, creds);

  if (res.data?.meta && res.data.meta.httpStatusCode !== 200) {
    const msg = res.data.meta.errorMessage || `HTTP error ${res.status}`;
    const code = res.data.meta.errorCode || res.status;
    throw new Error(`[Getcontact ${code}] ${msg}`);
  }

  const d = res.data?.result || {};
  return (d.tags || []).map((t) => ({
    tag: t.tag,
    count: t.count || 1
  }));
}

export async function getQuota(customCreds = null) {
  const creds = resolveCreds(customCreds);
  const res = await gtcCall('/v2.8/subscription', {
    token: creds.token
  }, creds);

  if (res.data?.meta && res.data.meta.httpStatusCode !== 200) {
    const msg = res.data.meta.errorMessage || `HTTP error ${res.status}`;
    const code = res.data.meta.errorCode || res.status;
    throw new Error(`[Getcontact ${code}] ${msg}`);
  }

  const usage = res.data?.result?.subscriptionInfo?.usage || {};
  return {
    renewDate: res.data?.result?.subscriptionInfo?.renewDate || '',
    searchRemaining: usage.search?.remainingCount ?? 0,
    searchLimit: usage.search?.limit ?? 0,
    detailRemaining: usage.numberDetail?.remainingCount ?? 0,
    detailLimit: usage.numberDetail?.limit ?? 0
  };
}
