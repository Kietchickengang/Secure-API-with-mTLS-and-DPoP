const { jwtVerify, importJWK, calculateJwkThumbprint } = require('jose');
const crypto = require('crypto');
const redis = require('./redisClient');

async function verifyDPoP(dpopHeader, rawAccessToken, accessTokenPayload, reqMethod, reqUrl) {
  if (!dpopHeader) throw new Error("Missing DPoP Header");

  const { payload: dpopPayload, protectedHeader } = await jwtVerify(
    dpopHeader,
    async (header) => {
      if (!header.jwk) throw new Error("DPoP Proof missing 'jwk' in header");
      return await importJWK(header.jwk, header.alg);
    }
  );

  const jti = dpopPayload.jti;
  if (!jti) throw new Error("Missing 'jti' in DPoP Proof");

  const iat = dpopPayload.iat;
  if (!iat) throw new Error("Missing 'iat' in DPoP Proof");
  const now = Math.floor(Date.now() / 1000);
  
  if (Math.abs(now - iat) > 60) {
    throw new Error(`DPoP proof expired or future-dated: iat=${iat}, now=${now}`);
  }

  const stored = await redis.set(`jti:${jti}`, 'used', 'NX', 'EX', 60);
  if (!stored) {
    throw new Error('DPoP jti replay attack: Token already used!');
  }

  if (dpopPayload.htm !== reqMethod || dpopPayload.htu !== reqUrl) {
    throw new Error(`DPoP htm/htu mismatch! Expected: ${reqMethod} ${reqUrl}`);
  }

  if (!dpopPayload.ath) throw new Error("Missing 'ath' in DPoP Proof");
  const expectedAth = crypto.createHash('sha256').update(rawAccessToken).digest('base64url');
  if (dpopPayload.ath !== expectedAth) {
    throw new Error("DPoP 'ath' Mismatch!");
  }

  const actualJkt = await calculateJwkThumbprint(protectedHeader.jwk, 'sha256');
  
  if (!accessTokenPayload.cnf || !accessTokenPayload.cnf.jkt) {
    throw new Error('Access Token does not contain cnf.jkt');
  }
  
  if (accessTokenPayload.cnf.jkt !== actualJkt) {
    throw new Error('DPoP Binding Mismatch (jkt)!');
  }

  return true;
}

module.exports = { verifyDPoP };