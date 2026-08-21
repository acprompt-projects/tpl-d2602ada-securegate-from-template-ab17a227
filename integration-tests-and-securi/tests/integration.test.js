const assert = require('assert');
const http = require('http');

const BASE = process.env.GATEWAY_URL || 'http://localhost:3000';
let adminToken, userToken, apiKey;

function request(method, path, body, headers = {}) {
  return new Promise((resolve, reject) => {
    const url = new URL(path, BASE);
    const opts = { hostname: url.hostname, port: url.port, path: url.pathname, method, headers: { 'Content-Type': 'application/json', ...headers } };
    const req = http.request(opts, res => {
      let data = '';
      res.on('data', c => data += c);
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: data ? JSON.parse(data) : {} }));
    });
    req.on('error', reject);
    if (body) req.write(JSON.stringify(body));
    req.end();
  });
}

async function authenticate(user, pass) {
  const r = await request('POST', '/auth/token', { username: user, password: pass, grant_type: 'password' });
  return r.body.access_token;
}

(async () => {
  console.log('=== Integration Tests ===\n');

  // 1. Auth flow
  adminToken = await authenticate('admin', 'adminpass');
  assert(adminToken, 'Admin token received');
  console.log('PASS: Admin login');

  userToken = await authenticate('user', 'userpass');
  assert(userToken, 'User token received');
  console.log('PASS: User login');

  const bad = await request('POST', '/auth/token', { username: 'admin', password: 'wrong', grant_type: 'password' });
  assert(bad.status === 401, 'Bad credentials rejected');
  console.log('PASS: Bad credentials → 401');

  // 2. RBAC
  const adminRes = await request('GET', '/admin/users', null, { Authorization: `Bearer ${adminToken}` });
  assert(adminRes.status === 200, 'Admin accesses /admin/users');
  console.log('PASS: Admin RBAC access');

  const userRes = await request('GET', '/admin/users', null, { Authorization: `Bearer ${userToken}` });
  assert(userRes.status === 403, 'User denied /admin/users');
  console.log('PASS: User RBAC denied → 403');

  const noAuth = await request('GET', '/admin/users');
  assert(noAuth.status === 401, 'No token → 401');
  console.log('PASS: No token → 401');

  // 3. API Key management
  const keyRes = await request('POST', '/api-keys', { name: 'test-key', roles: ['reader'] }, { Authorization: `Bearer ${adminToken}` });
  assert(keyRes.status === 201 && keyRes.body.key, 'API key created');
  apiKey = keyRes.body.key;
  console.log('PASS: API key created');

  const keyAuth = await request('GET', '/metrics/health', null, { 'X-API-Key': apiKey });
  assert(keyAuth.status === 200, 'API key authenticates');
  console.log('PASS: API key auth works');

  const badKey = await request('GET', '/metrics/health', null, { 'X-API-Key': 'invalid-key' });
  assert(badKey.status === 401, 'Invalid API key rejected');
  console.log('PASS: Bad API key → 401');

  // 4. Rate limiting
  let rateHit = false;
  for (let i = 0; i < 110; i++) {
    const r = await request('GET', '/metrics/health', null, { Authorization: `Bearer ${userToken}` });
    if (r.status === 429) { rateHit = true; break; }
  }
  assert(rateHit, 'Rate limit triggered → 429');
  console.log('PASS: Rate limiting works');

  // 5. Token tampering
  const tampered = adminToken.split('.').map((p, i) => i === 1 ? Buffer.from(JSON.stringify({ ...JSON.parse(Buffer.from(p, 'base64').toString()), role: 'superadmin' })).toString('base64url') : p).join('.');
  const tamperRes = await request('GET', '/admin/users', null, { Authorization: `Bearer ${tampered}` });
  assert(tamperRes.status === 401, 'Tampered token rejected');
  console.log('PASS: Token tampering → 401');

  // 6. Privilege escalation
  const escRes = await request('PUT', '/auth/token/role', { role: 'admin' }, { Authorization: `Bearer ${userToken}` });
  assert([403, 404, 405].includes(escRes.status), 'Privilege escalation blocked');
  console.log('PASS: Privilege escalation blocked');

  // 7. Expired token
  const expired = 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyIiwicm9sZSI6InVzZXIiLCJleHAiOjF9.expiredsig';
  const expRes = await request('GET', '/metrics/health', null, { Authorization: `Bearer ${expired}` });
  assert(expRes.status === 401, 'Expired/invalid token rejected');
  console.log('PASS: Expired token → 401');

  console.log('\n=== All Integration Tests Passed ===');
})().catch(e => { console.error('FAIL:', e.message); process.exit(1); });