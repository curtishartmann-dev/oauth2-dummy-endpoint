'use strict';

const path = require('path');
const express = require('express');
const morgan = require('morgan');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
const YAML = require('yamljs');
const swaggerUi = require('swagger-ui-express');

const PORT = parseInt(process.env.PORT, 10) || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'dev-only-secret-change-me';
const JWT_ISSUER = process.env.JWT_ISSUER || `http://localhost:${PORT}`;
const TOKEN_TTL = parseInt(process.env.TOKEN_TTL, 10) || 3600;

// Parse OAUTH_CLIENTS env: "id:secret:scope1 scope2,id2:secret2:scope"
function loadClients() {
  const raw = process.env.OAUTH_CLIENTS || 'demo-client:demo-secret:read write';
  const clients = {};
  for (const entry of raw.split(',')) {
    const trimmed = entry.trim();
    if (!trimmed) continue;
    const parts = trimmed.split(':');
    const id = parts[0];
    const secret = parts[1] || '';
    const scope = parts.slice(2).join(':') || '';
    if (id) clients[id] = { secret, allowedScopes: scope.split(/\s+/).filter(Boolean) };
  }
  return clients;
}

const CLIENTS = loadClients();
const REVOKED = new Set(); // jti set, in-memory only

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
  const ok = req.filter((s) => allowed.includes(s));
  return ok;
}

// ---------- discovery ----------
app.get('/.well-known/oauth-authorization-server', (req, res) => {
  res.json({
    issuer: JWT_ISSUER,
    token_endpoint: `${JWT_ISSUER}/oauth/token`,
    introspection_endpoint: `${JWT_ISSUER}/oauth/introspect`,
    userinfo_endpoint: `${JWT_ISSUER}/oauth/userinfo`,
    grant_types_supported: ['client_credentials'],
    token_endpoint_auth_methods_supported: ['client_secret_basic', 'client_secret_post'],
    response_types_supported: ['token'],
    scopes_supported: ['read', 'write'],
    id_token_signing_alg_values_supported: ['HS256'],
    service_documentation: `${JWT_ISSUER}/docs`,
  });
});

// ---------- token endpoint ----------
app.post('/oauth/token', (req, res) => {
  res.set('Cache-Control', 'no-store');
  res.set('Pragma', 'no-cache');

  const grant = req.body.grant_type;
  if (grant !== 'client_credentials') {
    return oauthError(
      res,
      400,
      'unsupported_grant_type',
      `Only client_credentials is supported, got "${grant}"`,
    );
  }

  const auth = authenticateClient(req, res);
  if (!auth) return; // response already sent

  const scopes = filterScopes(req.body.scope, auth.client.allowedScopes);
  const jti = uuidv4();
  const now = Math.floor(Date.now() / 1000);

  const payload = {
    iss: JWT_ISSUER,
    sub: auth.client_id,
    aud: JWT_ISSUER,
    client_id: auth.client_id,
    scope: scopes.join(' '),
    iat: now,
    exp: now + TOKEN_TTL,
    jti,
  };

  const access_token = jwt.sign(payload, JWT_SECRET, {
    algorithm: 'HS256',
    header: { typ: 'at+jwt' },
  });

  return res.json({
    access_token,
    token_type: 'Bearer',
    expires_in: TOKEN_TTL,
    scope: scopes.join(' '),
  });
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
  try {
    const decoded = jwt.verify(token, JWT_SECRET, { algorithms: ['HS256'] });
    REVOKED.add(decoded.jti);
  } catch (_) {
    /* per RFC 7009, invalid tokens still return 200 */
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
  });
});

// 404
app.use((req, res) => oauthError(res, 404, 'not_found', `No route for ${req.method} ${req.path}`));

app.listen(PORT, () => {
  console.log(`oauth2-dummy listening on :${PORT} (issuer=${JWT_ISSUER})`);
  console.log(`clients: ${Object.keys(CLIENTS).join(', ') || '(none)'}`);
});
