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
  const alreadyUsed = await redis.get(`jti:${jti}`);
  if (alreadyUsed) throw new Error('DPoP JTI Replay Attack: Token used!');
  await redis.setex(`jti:${jti}`, 3600, 'used');

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