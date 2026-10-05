// A THROWAWAY OAuth issuer for snout_oauth's end-to-end run (e2e/run.sh). Node 22, no
// dependencies. Never deployed, never reachable from outside this machine.
//
// It speaks just enough OAuth for libpq 18's device flow: discovery, a device authorization
// endpoint (RFC 8628), and a token endpoint that approves a device code on its first poll. Tokens
// are ES256 DATABASE tokens shaped as the real issuer's are:
// `token_use: "db"`, the role in `db_role` (never `role`), and `aud` the project ref, which it reads
// from the `db:<ref>` scope the SERVER asked for, as the real issuer does.
//
// Control endpoints, for the harness only:
//   GET /mode?next=<mode>&sign=<kid>   what the next token is, and which key signs it
//     modes: ok expired otheraud otherrole otherkey unknownkid otherissuer notokenuse session
//            rolebeside
//   GET /jwks?kids=k1,k2               a key file holding those public keys (the harness installs
//                                      it in the database the way the platform does)
//   GET /seen                          the client ids and scopes device authorization received
//
//   ISSUER=http://host.docker.internal:9998 PORT=9998 ROLE=alice node issuer.mjs
import { createServer } from 'node:http';
import { generateKeyPairSync, sign, randomBytes } from 'node:crypto';

const ISSUER = process.env.ISSUER ?? 'http://host.docker.internal:9998';
const PORT = Number(process.env.PORT ?? 9998);
const ROLE = process.env.ROLE ?? 'alice';

function newKey(kid) {
	const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
	const jwk = publicKey.export({ format: 'jwk' });
	return { kid, privateKey, jwk: { ...jwk, kid, alg: 'ES256', use: 'sig' } };
}

// k1 and k2 are publishable (rotation). `stranger` claims k1's kid with a key nobody published,
// and `k9` is a kid no key file ever names.
const keys = { k1: newKey('k1'), k2: newKey('k2'), k9: newKey('k9') };
const stranger = newKey('k1');

let mode = 'ok';
let signWith = 'k1';
const devices = new Map();
const seen = [];

function b64url(buf) {
	return Buffer.from(buf).toString('base64url');
}

function mint(scope) {
	const now = Math.floor(Date.now() / 1000);
	const ref = /(?:^| )db:([a-z0-9]+)(?: |$)/.exec(scope ?? '')?.[1];
	if (!ref) {
		return null;
	}
	const claims = {
		iss: mode === 'otherissuer' ? 'http://evil.example' : ISSUER,
		aud: mode === 'otheraud' ? 'someotherproj' : ref,
		sub: 'user-0001',
		email: 'alice@example.com',
		token_use: 'db',
		db_role: mode === 'otherrole' ? 'bob' : ROLE,
		iat: now,
		exp: mode === 'expired' ? now - 120 : now + 3600
	};
	if (mode === 'notokenuse') {
		delete claims.token_use;
	}
	if (mode === 'session') {
		// What a session token carries: `role`, no `db_role`.
		delete claims.db_role;
		claims.role = ROLE;
	}
	if (mode === 'rolebeside') {
		claims.role = 'authenticated';
	}
	const signer = mode === 'otherkey' ? stranger : mode === 'unknownkid' ? keys.k9 : keys[signWith];
	const header = { alg: 'ES256', typ: 'JWT', kid: signer.kid };
	const input = `${b64url(JSON.stringify(header))}.${b64url(JSON.stringify(claims))}`;
	const sig = sign('sha256', Buffer.from(input), { key: signer.privateKey, dsaEncoding: 'ieee-p1363' });
	console.log(`issuer: minted a token (mode ${mode}, kid ${signer.kid}, aud ${claims.aud})`);
	return `${input}.${b64url(sig)}`;
}

function json(res, status, body) {
	res.writeHead(status, { 'Content-Type': 'application/json' });
	res.end(JSON.stringify(body));
}

function readForm(req) {
	return new Promise((resolve) => {
		let data = '';
		req.on('data', (c) => {
			data += c;
		});
		req.on('end', () => resolve(new URLSearchParams(data)));
	});
}

const discovery = {
	issuer: ISSUER,
	token_endpoint: `${ISSUER}/token`,
	device_authorization_endpoint: `${ISSUER}/device`,
	jwks_uri: `${ISSUER}/jwks`,
	grant_types_supported: ['urn:ietf:params:oauth:grant-type:device_code'],
	response_types_supported: ['token'],
	token_endpoint_auth_methods_supported: ['none']
};

createServer(async (req, res) => {
	const url = new URL(req.url, ISSUER);
	if (url.pathname === '/.well-known/openid-configuration' || url.pathname === '/.well-known/oauth-authorization-server') {
		return json(res, 200, discovery);
	}
	if (url.pathname === '/jwks') {
		const kids = (url.searchParams.get('kids') ?? 'k1').split(',').filter((k) => keys[k]);
		return json(res, 200, { keys: kids.map((k) => keys[k].jwk) });
	}
	if (url.pathname === '/mode') {
		mode = url.searchParams.get('next') ?? 'ok';
		signWith = url.searchParams.get('sign') ?? signWith;
		return json(res, 200, { mode, signWith });
	}
	if (url.pathname === '/seen') {
		return json(res, 200, seen);
	}
	if (url.pathname === '/device' && req.method === 'POST') {
		const form = await readForm(req);
		const deviceCode = randomBytes(16).toString('hex');
		devices.set(deviceCode, form.get('scope'));
		seen.push({ client_id: form.get('client_id'), scope: form.get('scope') });
		console.log(`issuer: device authorization, client ${form.get('client_id')}, scope "${form.get('scope')}"`);
		return json(res, 200, {
			device_code: deviceCode,
			user_code: 'SNOUT-E2E1',
			verification_uri: `${ISSUER}/approve`,
			expires_in: 300,
			interval: 1
		});
	}
	if (url.pathname === '/token' && req.method === 'POST') {
		const form = await readForm(req);
		const code = form.get('device_code');
		if (form.get('grant_type') !== 'urn:ietf:params:oauth:grant-type:device_code' || !devices.has(code)) {
			return json(res, 400, { error: 'invalid_grant' });
		}
		const scope = devices.get(code);
		devices.delete(code);
		const token = mint(scope);
		if (!token) {
			// The issuer refuses when the server's scope names no project.
			return json(res, 400, { error: 'invalid_scope', error_description: 'the scope names no db:<ref>' });
		}
		return json(res, 200, { access_token: token, token_type: 'Bearer', expires_in: 3600 });
	}
	json(res, 404, { error: 'not_found' });
}).listen(PORT, () => console.log(`issuer: listening on ${PORT} as ${ISSUER}`));
