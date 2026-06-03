#!/bin/bash

export VALID_TOKEN=$(node -e "const fs = require('fs'); const { generateKeyPair, SignJWT, exportJWK, calculateJwkThumbprint } = require('jose'); const axios = require('axios'); const https = require('https'); const crypto = require('crypto'); (async () => {
  const { publicKey, privateKey } = await generateKeyPair('ES256');const privateJwk = await exportJWK(privateKey);fs.writeFileSync('my-dpop-key.json', JSON.stringify(privateJwk));const jwk = await exportJWK(publicKey);const jkt = await calculateJwkThumbprint(jwk);
  const dpopT = await new SignJWT({ htm: 'POST', htu: 'https://localhost:8443/realms/zero-trust-realm/protocol/openid-connect/token', jti: crypto.randomBytes(16).toString('hex') }).setProtectedHeader({ alg: 'ES256', jwk, typ: 'dpop+jwt' }).setIssuedAt().sign(privateKey);
  const res = await axios.post('https://localhost:8443/realms/zero-trust-realm/protocol/openid-connect/token', new URLSearchParams({ grant_type: 'client_credentials', client_id: 'api-gatewate-client', client_secret: 'Cf18q68tal79D5sQ8bVRnNSLV4roRFr3',dpop_jkt: jkt
  }), { headers: { 'DPoP': dpopT }, httpsAgent: new https.Agent({ rejectUnauthorized: false }) });console.log(res.data.access_token);})()")

export VALID_DPOP=$(node -e "const fs = require('fs'); const crypto = require('crypto'); const { importJWK, SignJWT } = require('jose'); (async () => {const privateJwk = JSON.parse(fs.readFileSync('my-dpop-key.json'));const privateKey = await importJWK(privateJwk, 'ES256');
  const { d, ...publicJwk } = privateJwk;const ath = crypto.createHash('sha256').update(process.env.VALID_TOKEN).digest('base64url');const dpop = await new SignJWT({ htm: 'GET', htu: 'https://192.168.49.2:31646/headers', jti: crypto.randomBytes(16).toString('hex'), ath }).
  setProtectedHeader({ alg: 'ES256', jwk: publicJwk, typ: 'dpop+jwt' }).setIssuedAt().sign(privateKey);console.log(dpop);})()")

export HACKER_DPOP=$(node -e "const { generateKeyPair, SignJWT, exportJWK } = require('jose'); const crypto = require('crypto'); (async () => {const { publicKey, privateKey } = await generateKeyPair('ES256');const jwk = await exportJWK(publicKey);
  const ath = crypto.createHash('sha256').update(process.env.VALID_TOKEN).digest('base64url');const dpop = await new SignJWT({ htm: 'GET', htu: 'https://192.168.49.2:31646/headers', jti: crypto.randomBytes(16).toString('hex'), ath })
  .setProtectedHeader({ alg: 'ES256', jwk, typ: 'dpop+jwt' }).setIssuedAt().sign(privateKey);console.log(dpop);})()")

export WRONG_URL_DPOP=$(node -e "const fs = require('fs'); const crypto = require('crypto'); const { importJWK, SignJWT } = require('jose'); (async () => { const privateJwk = JSON.parse(fs.readFileSync('my-dpop-key.json')); const privateKey = await importJWK(privateJwk, 'ES256'); 
  const { d, ...publicJwk } = privateJwk; const ath = crypto.createHash('sha256').update(process.env.VALID_TOKEN).digest('base64url'); const dpop = await new SignJWT({ htm: 'GET', htu: 'https://192.168.49.2:31646/xHelper', jti: crypto.randomBytes(16).toString('hex'), ath })
  .setProtectedHeader({ alg: 'ES256', jwk: publicJwk, typ: 'dpop+jwt' }).setIssuedAt().sign(privateKey); console.log(dpop); })()")

export WRONG_ATH_DPOP=$(node -e "const fs = require('fs'); const crypto = require('crypto'); const { importJWK, SignJWT } = require('jose'); (async () => { const privateJwk = JSON.parse(fs.readFileSync('my-dpop-key.json')); const privateKey = await importJWK(privateJwk, 'ES256'); 
  const { d, ...publicJwk } = privateJwk; const ath = crypto.createHash('sha256').update('HEHE_NO_ONE_KNOWS_I_FAKED_IT_:>').digest('base64url'); const dpop = await new SignJWT({ htm: 'GET', htu: 'https://192.168.49.2:31646/headers', jti: crypto.randomBytes(16).toString('hex'), ath })
  .setProtectedHeader({ alg: 'ES256', jwk: publicJwk, typ: 'dpop+jwt' }).setIssuedAt().sign(privateKey); console.log(dpop); })()")

export FUTURE_DPOP=$(node -e "const fs = require('fs'); const crypto = require('crypto'); const { importJWK, SignJWT } = require('jose'); (async () => { const privateJwk = JSON.parse(fs.readFileSync('my-dpop-key.json')); const privateKey = await importJWK(privateJwk, 'ES256'); 
  const { d, ...publicJwk } = privateJwk; const ath = crypto.createHash('sha256').update(process.env.VALID_TOKEN).digest('base64url'); const futureIat = Math.floor(Date.now() / 1000) + 120; const dpop = await new SignJWT({ htm: 'GET', htu: 'https://192.168.49.2:31646/headers', 
  jti: crypto.randomBytes(16).toString('hex'), ath, iat: futureIat }).setProtectedHeader({ alg: 'ES256', jwk: publicJwk, typ: 'dpop+jwt' }).sign(privateKey); console.log(dpop); })()")




