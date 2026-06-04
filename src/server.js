'use strict';

const path = require('path');
const crypto = require('crypto');
const express = require('express');
const morgan = require('morgan');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
const YAML = require('yamljs');
const swaggerUi = require('swagger-ui-express');

// ---------------------------------------------------------------------------
// DEMO CONFIG — all values hardcoded. Edit here if you need to change them.
// render.com sets PORT for you, so we still honor it if present.
// ---------------------------------------------------------------------------
const PORT = parseInt(process.env.PORT, 10) || 3000;
const JWT_SECRET = 'demo-super-secret-do-not-use-in-prod-1234567890';
const JWT_ISSUER = 'https://oauth2-dummy-endpoint.onrender.com';
const TOKEN_TTL = 3600;          // access token, seconds
const CODE_TTL = 600;            // authorization code, seconds
const REFRESH_TTL = 30 * 24 * 60 * 60; // refresh token, seconds (30 days)

// The "user" that authorization code grants are issued for. In a real server
// this would come from a login form; we hardcode a demo user.
const DEMO_USER = {
  sub: 'demo-user-001',
  email: 'demo-user@example.com',
  name: 'Demo User',
};

const CLIENTS = {
  'demo-client': {
    secret: 'demo-secret',
    allowedScopes: ['read', 'write', 'openid', 'profile', 'email'],
    redirectUris: [
      // RingCentral Token Manager callbacks
      'https://tokenmanager-dca14.ringcentral.com/token-manager/v2/oauth2callback',
      'https://tokenmanager-dca14-spare.ringcentral.com/token-manager/v2/oauth2callback',
      'https://tokenmanager-aws76.ringcentral.com/token-manager/v2/oauth2callback',
      // Common testing tools
      'https://oauth.pstmn.io/v1/callback',           // Postman
      'https://oauth.pstmn.io/v1/browser-callback',   // Postman browser
      'http://localhost:3000/callback',
      'http://localhost:8080/callback',
      'http://127.0.0.1:3000/callback',
    ],
  },
  'another-client': {
    secret: 'another-secret',
    allowedScopes: ['read'],
    redirectUris: ['http://localhost:3000/callback'],
  },
};
// ---------------------------------------------------------------------------

// In-memory stores (process-local; lost on restart). Fine for a demo.
const REVOKED = new Set();        // jti set
const CODES = new Map();          // code -> { client_id, redirect_uri, scope, user, code_challenge, code_challenge_method, expiresAt }
const REFRESH_TOKENS = new Map(); // refresh_token -> { client_id, scope, user, expiresAt }

const app = express();
app.disable('x-powered-by');
app.use(morgan('tiny'));
app.use(express.urlencoded({ extended: false }));
app.use(express.json());

// ---------- helpers ----------
function parseClientCredentials(req) {
  // Prefer HTTP Basic, fall back to form body (RFC 6749 §2.3.1)
  const header = req.headers.authorization || '';
  if (header.toLowerCase().startsWith('basic ')) {
    try {
      const decoded = Buffer.from(header.slice(6), 'base64').toString('utf8');
      const idx = decoded.indexOf(':');
      if (idx > -1) {
        return {
          client_id: decodeURIComponent(decoded.slice(0, idx)),
          client_secret: decodeURIComponent(decoded.slice(idx + 1)),
        };
      }
    } catch (_) {
      /* fallthrough */
    }
  }
  return {
    client_id: req.body.client_id,
    client_secret: req.body.client_secret,
  };
}

function oauthError(res, status, error, description) {
  return res.status(status).json({ error, error_description: description });
}

function authenticateClient(req, res) {
  const { client_id, client_secret } = parseClientCredentials(req);
  if (!client_id || !client_secret) {
    oauthError(res, 401, 'invalid_client', 'Missing client credentials');
    return null;
  }
  const client = CLIENTS[client_id];
  if (!client || client.secret !== client_secret) {
    oauthError(res, 401, 'invalid_client', 'Invalid client credentials');
    return null;
  }
  return { client_id, client };
}

function filterScopes(requested, allowed) {
  if (!requested) return allowed;
  const req = requested.split(/\s+/).filter(Boolean);
  return req.filter((s) => allowed.includes(s));
}

function base64url(buf) {
  return buf.toString('base64').replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
}

function verifyPkce(code_verifier, code_challenge, method) {
  if (!code_challenge) return true; // PKCE was not used
  if (!code_verifier) return false;
  if (method === 'plain' || !method) return code_verifier === code_challenge;
  if (method === 'S256') {
    const hash = base64url(crypto.createHash('sha256').update(code_verifier).digest());
    return hash === code_challenge;
  }
  return false;
}

function issueAccessToken({ client_id, scope, user }) {
  const jti = uuidv4();
  const now = Math.floor(Date.now() / 1000);
  const payload = {
    iss: JWT_ISSUER,
    sub: user ? user.sub : client_id,
    aud: JWT_ISSUER,
    client_id,
    scope,
    iat: now,
    exp: now + TOKEN_TTL,
    jti,
  };
  if (user) {
    payload.email = user.email;
    payload.name = user.name;
  }
  return jwt.sign(payload, JWT_SECRET, { algorithm: 'HS256', header: { typ: 'at+jwt' } });
}

function issueRefreshToken({ client_id, scope, user }) {
  const token = base64url(crypto.randomBytes(32));
  REFRESH_TOKENS.set(token, {
    client_id,
    scope,
    user,
    expiresAt: Date.now() + REFRESH_TTL * 1000,
  });
  return token;
}

// ---------- discovery ----------
app.get('/.well-known/oauth-authorization-server', (req, res) => {
  res.json({
    issuer: JWT_ISSUER,
    authorization_endpoint: `${JWT_ISSUER}/oauth/authorize`,
    token_endpoint: `${JWT_ISSUER}/oauth/token`,
    introspection_endpoint: `${JWT_ISSUER}/oauth/introspect`,
    revocation_endpoint: `${JWT_ISSUER}/oauth/revoke`,
    userinfo_endpoint: `${JWT_ISSUER}/oauth/userinfo`,
    grant_types_supported: ['authorization_code', 'client_credentials', 'refresh_token'],
    response_types_supported: ['code'],
    token_endpoint_auth_methods_supported: ['client_secret_basic', 'client_secret_post'],
    code_challenge_methods_supported: ['plain', 'S256'],
    scopes_supported: ['read', 'write', 'openid', 'profile', 'email'],
    id_token_signing_alg_values_supported: ['HS256'],
    service_documentation: `${JWT_ISSUER}/docs`,
  });
});

// ---------- authorization endpoint ----------
// GET shows a tiny consent page. POST records consent and redirects with code.
function validateAuthorizeParams(query) {
  const errors = [];
  if (query.response_type !== 'code') errors.push('response_type must be "code"');
  if (!query.client_id) errors.push('client_id is required');
  if (!query.redirect_uri) errors.push('redirect_uri is required');
  const client = CLIENTS[query.client_id];
  if (!client) errors.push('unknown client_id');
  if (client && !client.redirectUris.includes(query.redirect_uri)) {
    errors.push('redirect_uri is not registered for this client');
  }
  return { errors, client };
}

app.get('/oauth/authorize', (req, res) => {
  const { errors, client } = validateAuthorizeParams(req.query);
  if (errors.length) {
    // Per RFC 6749 §4.1.2.1, errors with invalid client/redirect must NOT redirect.
    return res.status(400).send(`<h1>Authorization error</h1><ul>${errors.map(e => `<li>${e}</li>`).join('')}</ul>`);
  }

  const scopes = filterScopes(req.query.scope, client.allowedScopes);
  const params = new URLSearchParams({
    response_type: 'code',
    client_id: req.query.client_id,
    redirect_uri: req.query.redirect_uri,
    scope: scopes.join(' '),
    state: req.query.state || '',
    code_challenge: req.query.code_challenge || '',
    code_challenge_method: req.query.code_challenge_method || '',
  });

  res.set('Content-Type', 'text/html; charset=utf-8');
  res.send(`<!doctype html>
<html><head><title>Authorize — OAuth 2.0 Dummy</title>
<style>
  body{font-family:system-ui,sans-serif;max-width:480px;margin:40px auto;padding:20px;background:#f7f7f7}
  .card{background:#fff;padding:24px;border-radius:8px;box-shadow:0 2px 6px rgba(0,0,0,.08)}
  h1{margin-top:0;font-size:20px} .meta{color:#666;font-size:13px;margin:8px 0}
  code{background:#eee;padding:2px 6px;border-radius:3px}
  button{background:#0066ff;color:#fff;border:0;padding:10px 18px;border-radius:6px;font-size:15px;cursor:pointer;margin-right:8px}
  button.cancel{background:#999}
  ul{padding-left:20px} li{margin:4px 0}
</style></head>
<body><div class="card">
  <h1>Authorize <code>${req.query.client_id}</code></h1>
  <div class="meta">User: <strong>${DEMO_USER.email}</strong> (demo)</div>
  <div class="meta">Redirect: <code>${req.query.redirect_uri}</code></div>
  <p>The application is requesting the following permissions:</p>
  <ul>${scopes.map(s => `<li><code>${s}</code></li>`).join('') || '<li>(no scopes)</li>'}</ul>
  <form method="POST" action="/oauth/authorize?${params.toString()}">
    <button type="submit" name="action" value="approve">Approve</button>
    <button type="submit" name="action" value="deny" class="cancel">Deny</button>
  </form>
</div></body></html>`);
});

app.post('/oauth/authorize', (req, res) => {
  const { errors, client } = validateAuthorizeParams(req.query);
  if (errors.length) {
    return res.status(400).json({ error: 'invalid_request', error_description: errors.join('; ') });
  }
  const redirect = new URL(req.query.redirect_uri);
  if (req.query.state) redirect.searchParams.set('state', req.query.state);

  if (req.body.action !== 'approve') {
    redirect.searchParams.set('error', 'access_denied');
    redirect.searchParams.set('error_description', 'User denied the request');
    return res.redirect(302, redirect.toString());
  }

  const scopes = filterScopes(req.query.scope, client.allowedScopes);
  const code = base64url(crypto.randomBytes(24));
  CODES.set(code, {
    client_id: req.query.client_id,
    redirect_uri: req.query.redirect_uri,
    scope: scopes.join(' '),
    user: DEMO_USER,
    code_challenge: req.query.code_challenge || null,
    code_challenge_method: req.query.code_challenge_method || null,
    expiresAt: Date.now() + CODE_TTL * 1000,
  });

  redirect.searchParams.set('code', code);
  return res.redirect(302, redirect.toString());
});

// ---------- token endpoint ----------
app.post('/oauth/token', (req, res) => {
  res.set('Cache-Control', 'no-store');
  res.set('Pragma', 'no-cache');

  const grant = req.body.grant_type;

  if (grant === 'client_credentials') {
    const auth = authenticateClient(req, res);
    if (!auth) return;
    const scopes = filterScopes(req.body.scope, auth.client.allowedScopes);
    const access_token = issueAccessToken({
      client_id: auth.client_id,
      scope: scopes.join(' '),
      user: null,
    });
    return res.json({
      access_token,
      token_type: 'Bearer',
      expires_in: TOKEN_TTL,
      scope: scopes.join(' '),
    });
  }

  if (grant === 'authorization_code') {
    const code = req.body.code;
    if (!code) return oauthError(res, 400, 'invalid_request', 'Missing code');
    const entry = CODES.get(code);
    if (!entry) return oauthError(res, 400, 'invalid_grant', 'Unknown or used code');
    CODES.delete(code); // single-use
    if (entry.expiresAt < Date.now()) return oauthError(res, 400, 'invalid_grant', 'Code expired');

    // Client auth: required unless PKCE was used (then client_id is required, secret optional for public clients).
    const { client_id, client_secret } = parseClientCredentials(req);
    if (client_id !== entry.client_id) {
      return oauthError(res, 400, 'invalid_grant', 'client_id mismatch');
    }
    const client = CLIENTS[client_id];
    if (!client) return oauthError(res, 401, 'invalid_client', 'Unknown client');
    if (!entry.code_challenge) {
      // No PKCE: client_secret is required (confidential client).
      if (client.secret !== client_secret) {
        return oauthError(res, 401, 'invalid_client', 'Invalid client credentials');
      }
    } else if (client_secret && client.secret !== client_secret) {
      // Secret provided but wrong.
      return oauthError(res, 401, 'invalid_client', 'Invalid client credentials');
    }

    if (req.body.redirect_uri !== entry.redirect_uri) {
      return oauthError(res, 400, 'invalid_grant', 'redirect_uri mismatch');
    }

    if (!verifyPkce(req.body.code_verifier, entry.code_challenge, entry.code_challenge_method)) {
      return oauthError(res, 400, 'invalid_grant', 'PKCE verification failed');
    }

    const access_token = issueAccessToken({
      client_id: entry.client_id,
      scope: entry.scope,
      user: entry.user,
    });
    const refresh_token = issueRefreshToken({
      client_id: entry.client_id,
      scope: entry.scope,
      user: entry.user,
    });
    return res.json({
      access_token,
      token_type: 'Bearer',
      expires_in: TOKEN_TTL,
      refresh_token,
      scope: entry.scope,
    });
  }

  if (grant === 'refresh_token') {
    const auth = authenticateClient(req, res);
    if (!auth) return;
    const token = req.body.refresh_token;
    if (!token) return oauthError(res, 400, 'invalid_request', 'Missing refresh_token');
    const entry = REFRESH_TOKENS.get(token);
    if (!entry) return oauthError(res, 400, 'invalid_grant', 'Unknown refresh_token');
    if (entry.client_id !== auth.client_id) {
      return oauthError(res, 400, 'invalid_grant', 'client mismatch');
    }
    if (entry.expiresAt < Date.now()) {
      REFRESH_TOKENS.delete(token);
      return oauthError(res, 400, 'invalid_grant', 'refresh_token expired');
    }
    // Optionally narrow the scope on refresh.
    let scope = entry.scope;
    if (req.body.scope) {
      const requested = req.body.scope.split(/\s+/).filter(Boolean);
      const current = entry.scope.split(/\s+/).filter(Boolean);
      const narrowed = requested.filter((s) => current.includes(s));
      if (narrowed.length) scope = narrowed.join(' ');
    }
    const access_token = issueAccessToken({
      client_id: entry.client_id,
      scope,
      user: entry.user,
    });
    return res.json({
      access_token,
      token_type: 'Bearer',
      expires_in: TOKEN_TTL,
      scope,
    });
  }

  return oauthError(
    res,
    400,
    'unsupported_grant_type',
    `grant_type "${grant}" is not supported`,
  );
});

// ---------- introspection (RFC 7662) ----------
app.post('/oauth/introspect', (req, res) => {
  const auth = authenticateClient(req, res);
  if (!auth) return;

  const token = req.body.token;
  if (!token) return res.json({ active: false });

  try {
    const decoded = jwt.verify(token, JWT_SECRET, {
      algorithms: ['HS256'],
      issuer: JWT_ISSUER,
    });
    if (REVOKED.has(decoded.jti)) return res.json({ active: false });
    return res.json({
      active: true,
      scope: decoded.scope,
      client_id: decoded.client_id,
      token_type: 'Bearer',
      exp: decoded.exp,
      iat: decoded.iat,
      sub: decoded.sub,
      aud: decoded.aud,
      iss: decoded.iss,
      jti: decoded.jti,
    });
  } catch (_) {
    return res.json({ active: false });
  }
});

// ---------- userinfo ----------
app.get('/oauth/userinfo', (req, res) => {
  const header = req.headers.authorization || '';
  if (!header.toLowerCase().startsWith('bearer ')) {
    res.set('WWW-Authenticate', 'Bearer realm="oauth2-dummy"');
    return oauthError(res, 401, 'invalid_token', 'Missing bearer token');
  }
  const token = header.slice(7);
  try {
    const decoded = jwt.verify(token, JWT_SECRET, {
      algorithms: ['HS256'],
      issuer: JWT_ISSUER,
    });
    if (REVOKED.has(decoded.jti)) {
      return oauthError(res, 401, 'invalid_token', 'Token revoked');
    }
    return res.json({
      sub: decoded.sub,
      client_id: decoded.client_id,
      scope: decoded.scope,
      email: decoded.email,
      name: decoded.name,
      iss: decoded.iss,
      aud: decoded.aud,
      exp: decoded.exp,
    });
  } catch (err) {
    return oauthError(res, 401, 'invalid_token', err.message);
  }
});

// ---------- revoke (RFC 7009) ----------
app.post('/oauth/revoke', (req, res) => {
  const auth = authenticateClient(req, res);
  if (!auth) return;
  const token = req.body.token;
  if (!token) return res.status(200).end();
  // Try JWT (access token); if that fails, try refresh tokens.
  try {
    const decoded = jwt.verify(token, JWT_SECRET, { algorithms: ['HS256'] });
    REVOKED.add(decoded.jti);
  } catch (_) {
    REFRESH_TOKENS.delete(token);
  }
  return res.status(200).end();
});

// ---------- health & docs ----------
app.get('/healthz', (req, res) => res.json({ status: 'ok' }));

const openapiPath = path.join(__dirname, '..', 'openapi.yaml');
try {
  const openapiDoc = YAML.load(openapiPath);
  app.get('/openapi.yaml', (req, res) => res.sendFile(openapiPath));
  app.use('/docs', swaggerUi.serve, swaggerUi.setup(openapiDoc));
} catch (err) {
  console.warn('openapi.yaml not found; /docs disabled:', err.message);
}

app.get('/', (req, res) => {
  res.json({
    name: 'oauth2-dummy-endpoint',
    docs: `${JWT_ISSUER}/docs`,
    discovery: `${JWT_ISSUER}/.well-known/oauth-authorization-server`,
    grants: ['authorization_code', 'client_credentials', 'refresh_token'],
  });
});

// 404
app.use((req, res) => oauthError(res, 404, 'not_found', `No route for ${req.method} ${req.path}`));

app.listen(PORT, () => {
  console.log(`oauth2-dummy listening on :${PORT} (issuer=${JWT_ISSUER})`);
  console.log(`clients: ${Object.keys(CLIENTS).join(', ')}`);
});
