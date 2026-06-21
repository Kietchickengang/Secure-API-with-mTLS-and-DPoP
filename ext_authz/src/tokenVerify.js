const { jwtVerify, createRemoteJWKSet } = require('jose');
const config = require('./config');

// Manage JWKS from KeyCloak
const JWKS = createRemoteJWKSet(new URL(config.JWKS_URL));

async function verifyAccessToken(token) {
  const { payload } = await jwtVerify(token, JWKS, {
    issuer: config.ISSUER,
    clockTolerance: 30,
    audience: config.AUDIENCE,
    algorithms: config.ALGORITHMS,
  });
  return payload;
}

module.exports = { verifyAccessToken };