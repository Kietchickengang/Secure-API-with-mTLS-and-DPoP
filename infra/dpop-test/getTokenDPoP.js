const axios = require('axios');
const https = require('https');
const fs = require('fs');
const { generateKeyPair, SignJWT, exportJWK, calculateJwkThumbprint } = require('jose');
const crypto = require('crypto');

async function runZeroTrustTest() {
  console.log('[1] Initializing mTLS configuration...');
  
  // Agent for Keycloak (uses client.crt)
  const keycloakAgent = new https.Agent({
    cert: fs.readFileSync('client.crt'),
    key: fs.readFileSync('client.key'),
    rejectUnauthorized: false
  });

  // Agent for Envoy (uses valid-client.crt)
  const envoyAgent = new https.Agent({
    cert: fs.readFileSync('valid-client.crt'),
    key: fs.readFileSync('valid-client.key'),
    ca: fs.readFileSync('vault-ca.crt'),
    rejectUnauthorized: false
  });

  console.log('[2] Generating DPoP key pair...');
  const { publicKey, privateKey } = await generateKeyPair('ES256');
  const publicJwk = await exportJWK(publicKey);
  const jkt = await calculateJwkThumbprint(publicJwk);
  console.log(`   -> Successfully generated DPoP Thumbprint (jkt): ${jkt}`);

  console.log('\n[3] Requesting Access Token from Keycloak with DPoP...');
  const keycloakUrl = 'https://localhost:8443/realms/zero-trust-realm/protocol/openid-connect/token';
  
  const dpopForToken = await new SignJWT({
    htm: 'POST',
    htu: keycloakUrl,
    jti: crypto.randomUUID(),
  })
    .setProtectedHeader({ alg: 'ES256', jwk: publicJwk, typ: 'dpop+jwt' })
    .setIssuedAt()
    .sign(privateKey);

  let accessToken = '';
  try {
    const tokenParams = new URLSearchParams({
      grant_type: 'password',
      client_id: 'api-gatewate-client',
      username: 'k13t-du0n9',
      password: 'khonggiquyhondoclaptudo'
    });

    const tokenRes = await axios.post(keycloakUrl, tokenParams, {
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'DPoP': dpopForToken
      },
      httpsAgent: keycloakAgent
    });
    
    accessToken = tokenRes.data.access_token;
    console.log('   -> Successfully retrieved Access Token from Keycloak.');
    
    const payload = JSON.parse(Buffer.from(accessToken.split('.')[1], 'base64').toString());
    console.log('   -> Check cnf claim: ', payload.cnf);
  } catch (err) {
    console.error('   -> Error fetching Keycloak Token: ', err.response?.data || err.message);
    return;
  }

  console.log('\n[4] Generating DPoP Proof for Envoy API...');
  // Only print out headers (not all data) if success
  const apiUrl = 'https://192.168.49.2:31646/headers';
  const ath = crypto.createHash('sha256').update(accessToken).digest('base64url');
  const dpopForApi = await new SignJWT({
    htm: 'GET',
    htu: apiUrl,
    jti: crypto.randomUUID(),
    ath
  })
    .setProtectedHeader({ alg: 'ES256', jwk: publicJwk, typ: 'dpop+jwt' })
    .setIssuedAt()
    .sign(privateKey);
    
  console.log('   -> Generated DPoP Header:\n      ', dpopForApi.substring(0, 50) + '...');

  console.log('\n[5] Sending request to Envoy (mTLS + DPoP + Access Token)...');
  try {
    const apiRes = await axios.get(apiUrl, {
      headers: {
        'Authorization': `DPoP ${accessToken}`, 
        'DPoP': dpopForApi
      },
      httpsAgent: envoyAgent
    });
    
    console.log('\nSUCCESS!');
    console.log('HTTP Status:', apiRes.status);
    console.log('Response data:', apiRes.data);
  } catch (err) {
    console.error('\nFAILURE AT ENVOY/AUTHZ');
    console.error('HTTP Status:', err.response?.status);
    console.error('Reason:', err.response?.data || err.message);
    console.log('\n(Check `kubectl logs -l app=ext-authz` for detailed rejection reasons)');
  }
}

runZeroTrustTest();
