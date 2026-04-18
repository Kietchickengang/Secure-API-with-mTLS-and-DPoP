function verifyMTLSBinding(certHeader, accessTokenPayload) {
  if (!certHeader) throw new Error('Missing Client Certificate for mTLS');

  // Envoy send format: Hash=sha256_hex;Subject="..."
  const match = certHeader.match(/Hash=([a-f0-9]+)/i);
  const certThumbprint = match ? match[1].toLowerCase() : null;

  // Match with cnf['x5t#S256'] in token
  const tokenThumbprint = accessTokenPayload.cnf?.['x5t#S256'];
  
  if (!tokenThumbprint || certThumbprint !== tokenThumbprint.toLowerCase()) {
    throw new Error('mTLS Certificate Binding Mismatch');
  }
  return true;
}

module.exports = { verifyMTLSBinding };