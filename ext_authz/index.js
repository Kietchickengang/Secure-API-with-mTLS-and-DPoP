const express = require('express');
const config = require('./src/config');
const { verifyAccessToken } = require('./src/tokenVerify');
const { verifyDPoP } = require('./src/dpopVerify');
const { verifyMTLSBinding } = require('./src/certUtils');

const app = express();
app.use(express.json());

app.post('/auth', async (req, res) => {
  try {
    const authHeader = req.headers['authorization'];
    const dpopHeader = req.headers['dpop'];
    const certHeader = req.headers['x-forwarded-client-cert'];

    if (!authHeader) return res.status(401).send('Unauthorized');

    const token = authHeader.replace('DPoP ', '').replace('Bearer ', '');
    
    // Verify Token Signature (JWKS Keycloak)
    const payload = await verifyAccessToken(token);

    // Check Binding
    if (authHeader.startsWith('DPoP')) {
      // Verify DPoP for User/Mobile
      const fullUrl = `${req.headers['x-forwarded-proto'] || 'http'}://${req.headers['host']}${req.url}`;
      await verifyDPoP(dpopHeader, payload, req.method, fullUrl);
    } else {
      // Verify binding for Machine client
      verifyMTLSBinding(certHeader, payload);
    }

    // Enforcement
    console.log(`[Success] Authorized: ${payload.sub}`);
    res.setHeader('x-auth-user', payload.sub);
    return res.status(200).send('OK');

  } 
  catch (error) {
    console.error(`[Forbidden] ${error.message}`);
    return res.status(403).send(error.message);
  }
});

app.listen(config.PORT, () => {
  console.log(`Ext_Authz Service running on port ${config.PORT}`);
});