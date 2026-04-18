const { jwtVerify, importJWK, calculateJwkThumbprint } = require('jose');
const redis = require('./redisClient');

async function verifyDPoP(dpopHeader, accessTokenPayload, reqMethod, reqUrl) {
  // Decode & Verify DPoP Proof JWT (signed by Client Key)
  // Note: DPoP Proof includes public key in header 'jwk'
  const { payload: dpopPayload, protectedHeader } = await jwtVerify(
    dpopHeader,
    async (header) => await importJWK(header.jwk, header.alg)
  );

  // Check Replay Attack by "jti" in Redis
  const jti = dpopPayload.jti;
  const alreadyUsed = await redis.get(`jti:${jti}`);
  if (alreadyUsed) throw new Error('DPoP JTI Replay Attack');
  await redis.setex(`jti:${jti}`, 3600, 'used'); // Lưu 1 tiếng

  // Check htm (Method) & htu (URL) to ensure Proof bind with request
  if (dpopPayload.htm !== reqMethod || dpopPayload.htu !== reqUrl) {
    throw new Error('DPoP htm/htu mismatch');
  }

  // Match Thumbprint (jkt) with claim 'cnf' in Access Token
  const actualJkt = await calculateJwkThumbprint(protectedHeader.jwk);
  if (accessTokenPayload.cnf?.jkt !== actualJkt) {
    throw new Error('DPoP Binding Mismatch (jkt)');
  }

  return true;
}

module.exports = { verifyDPoP };