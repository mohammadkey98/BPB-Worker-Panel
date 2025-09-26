// Replaced heavy `jose` with Web Crypto (HMAC HS256) and removed `tweetnacl` usage here
import { renderLoginPage } from '../pages/login';

async function generateJWTToken (request, env) {
    const password = await request.text();
    const savedPass = await env.bpb.get('pwd');
    if (password !== savedPass) return new Response('Method Not Allowed', { status: 405 });
    let secretKey = await env.bpb.get('secretKey');
    if (!secretKey) {
        secretKey = generateSecretKey();
        await env.bpb.put('secretKey', secretKey);
    }
    const secret = new TextEncoder().encode(secretKey);
    const nowSeconds = Math.floor(Date.now() / 1000);
    const payload = {
        userID: globalThis.userID,
        iat: nowSeconds,
        exp: nowSeconds + 24 * 60 * 60
    };
    const jwtToken = await signJWT(payload, secret);

    return new Response('Success', {
        status: 200,
        headers: {
            'Set-Cookie': `jwtToken=${jwtToken}; HttpOnly; Secure; Max-Age=${7 * 24 * 60 * 60}; Path=/; SameSite=Strict`,
            'Content-Type': 'text/plain',
        }
    });
}

function generateSecretKey () {
    const array = new Uint8Array(32);
    crypto.getRandomValues(array);
    return Array.from(array, byte => byte.toString(16).padStart(2, '0')).join('');
}
  
export async function Authenticate (request, env) {
    try {
        const secretKey = await env.bpb.get('secretKey');
        const secret = new TextEncoder().encode(secretKey);
        const cookie = request.headers.get('Cookie')?.match(/(^|;\s*)jwtToken=([^;]*)/);
        const token = cookie ? cookie[2] : null;

        if (!token) {
            console.log('Unauthorized: Token not available!');
            return false;
        }

        const verified = await verifyJWT(token, secret);
        if (!verified.valid) {
            console.log('Unauthorized: Invalid token!');
            return false;
        }
        console.log(`Successfully authenticated, User ID: ${verified.payload.userID}`);
        return true;
    } catch (error) {
        console.log(error);
        return false;
    }
}

export function logout() {
    return new Response('Success', {
        status: 200,
        headers: {
            'Set-Cookie': 'jwtToken=; Secure; SameSite=None; Expires=Thu, 01 Jan 1970 00:00:00 GMT',
            'Content-Type': 'text/plain'
        }
    });
}

export async function resetPassword(request, env) {
    let auth = await Authenticate(request, env);
    const oldPwd = await env.bpb.get('pwd');
    if (oldPwd && !auth) return new Response('Unauthorized!', { status: 401 });           
    const newPwd = await request.text();
    if (newPwd === oldPwd) return new Response('Please enter a new Password!', { status: 400 });
    await env.bpb.put('pwd', newPwd);
    return new Response('Success', {
        status: 200,
        headers: {
            'Set-Cookie': 'jwtToken=; Path=/; Secure; SameSite=None; Expires=Thu, 01 Jan 1970 00:00:00 GMT',
            'Content-Type': 'text/plain',
        }
    });
}

export async function login(request, env) {
    const auth = await Authenticate(request, env);
    if (auth) return Response.redirect(`${globalThis.urlOrigin}/panel`, 302);
    if (request.method === 'POST') return await generateJWTToken(request, env);
    return await renderLoginPage();
}

// --- Minimal JWT HS256 implementation using Web Crypto ---
function base64UrlEncode(buffer) {
    const bytes = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
    let binary = '';
    for (let i = 0; i < bytes.byteLength; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    const base64 = btoa(binary);
    return base64.replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
}

function base64UrlEncodeString(str) {
    return base64UrlEncode(new TextEncoder().encode(str));
}

function base64UrlDecodeToUint8Array(b64url) {
    const base64 = b64url.replace(/-/g, '+').replace(/_/g, '/');
    const pad = base64.length % 4 === 0 ? '' : '='.repeat(4 - (base64.length % 4));
    const normalized = base64 + pad;
    const binary = atob(normalized);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
        bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
}

async function importHmacKey(secretBytes) {
    return await crypto.subtle.importKey(
        'raw',
        secretBytes,
        { name: 'HMAC', hash: 'SHA-256' },
        false,
        ['sign', 'verify']
    );
}

async function signJWT(payloadObject, secretBytes) {
    const headerJson = JSON.stringify({ alg: 'HS256', typ: 'JWT' });
    const payloadJson = JSON.stringify(payloadObject);
    const header = base64UrlEncodeString(headerJson);
    const payload = base64UrlEncodeString(payloadJson);
    const unsigned = `${header}.${payload}`;

    const key = await importHmacKey(secretBytes);
    const signature = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(unsigned));
    const signatureB64url = base64UrlEncode(new Uint8Array(signature));
    return `${unsigned}.${signatureB64url}`;
}

async function verifyJWT(token, secretBytes) {
    const parts = token.split('.');
    if (parts.length !== 3) return { valid: false };
    const [headerB64, payloadB64, signatureB64] = parts;
    const unsigned = `${headerB64}.${payloadB64}`;
    const key = await importHmacKey(secretBytes);
    const signatureBytes = base64UrlDecodeToUint8Array(signatureB64);
    const ok = await crypto.subtle.verify('HMAC', key, signatureBytes, new TextEncoder().encode(unsigned));
    if (!ok) return { valid: false };
    try {
        const payloadJson = new TextDecoder().decode(base64UrlDecodeToUint8Array(payloadB64));
        const payload = JSON.parse(payloadJson);
        const now = Math.floor(Date.now() / 1000);
        if (payload.exp && now >= payload.exp) return { valid: false };
        return { valid: true, payload };
    } catch (_) {
        return { valid: false };
    }
}