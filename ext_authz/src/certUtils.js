const crypto = require('crypto');

function verifyMTLSBinding(certHeader, accessTokenPayload) {
  console.log("\n---[mTLS Debug Check]---");
  console.log("1. Raw certHeader from Envoy:", certHeader);
  console.log("2. Token cnf payload:", accessTokenPayload?.cnf);

  if (!certHeader) {
    throw new Error('Missing Client Certificate for mTLS (Envoy did not pass XFCC header)');
  }

  const certHeaderStr = String(certHeader);
  
  // Envoy send format: Hash=sha256_hex;Subject="..."
  const match = certHeaderStr.match(/Hash=([a-f0-9]+)/i);
  const certThumbprint = match ? match[1].toLowerCase() : null;
  console.log("3. Extracted Cert Thumbprint:", certThumbprint);

  // Match with cnf['x5t#S256'] in token
  const tokenThumbprint = accessTokenPayload?.cnf?.['x5t#S256'];
  console.log("4. Extracted Token Thumbprint:", tokenThumbprint);
  
  if (!tokenThumbprint) {
    throw new Error('mTLS Binding Failed: no cnf.x5t#S256 in token');
  }
  if (!certThumbprint) {
    throw new Error('mTLS Binding Failed: no cert thumbprint from Envoy');
  }

  const a = Buffer.from(certThumbprint);
  const b = Buffer.from(tokenThumbprint.toLowerCase());
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) {
    throw new Error('mTLS Certificate Binding Mismatch');
  }

  console.log("-> [mTLS Result]: PASS OK!");
  return true;
}

module.exports = { verifyMTLSBinding };