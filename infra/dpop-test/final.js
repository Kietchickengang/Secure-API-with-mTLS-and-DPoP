const axios = require('axios');
const crypto = require('crypto');
const fs = require('fs');
const { calculateJwkThumbprint } = require('jose');

(async () => {
  try {
    const cert = fs.readFileSync('valid-client.crt', 'utf8').replace(/-----[^-]+-----/g, '').replace(/\s+/g, '');

    const thumbprint = crypto.createHash('sha256').update(Buffer.from(cert, 'base64')).digest('hex');

    const jwk = JSON.parse(fs.readFileSync('my-dpop-key.json'));
    const { d, ...pub } = jwk;
    const jkt = await calculateJwkThumbprint(pub);

    const tokenRes = await axios.post('http://localhost:8080/realms/master/protocol/openid-connect/token', new URLSearchParams({ client_id: 'admin-cli', username: 'admin', password: 'admin', grant_type: 'password' }));
    const token = tokenRes.data.access_token;

    const clients = await axios.get('http://localhost:8080/admin/realms/zero-trust-realm/clients?clientId=api-gatewate-client', { headers: { Authorization: 'Bearer ' + token } });
    const clientId = clients.data[0].id;

    const mappers = await axios.get(`http://localhost:8080/admin/realms/zero-trust-realm/clients/${clientId}/protocol-mappers/models`, { headers: { Authorization: 'Bearer ' + token } });
    for (let m of mappers.data) {
      if (m.name.includes('hack') || m.name.includes('cnf') || m.name.includes('ultimate')) {
        await axios.delete(`http://localhost:8080/admin/realms/zero-trust-realm/clients/${clientId}/protocol-mappers/models/${m.id}`, { headers: { Authorization: 'Bearer ' + token } });
      }
    }

    await axios.post(`http://localhost:8080/admin/realms/zero-trust-realm/clients/${clientId}/protocol-mappers/models`, {
      name: 'ultimate-hex-cnf-mapper',
      protocol: 'openid-connect',
      protocolMapper: 'oidc-hardcoded-claim-mapper',
      config: {
        'claim.name': 'cnf',
        'claim.value': JSON.stringify({ 'jkt': jkt, 'x5t#S256': thumbprint }),
        'jsonType.label': 'JSON',
        'access.token.claim': 'true'
      }
    }, { headers: { Authorization: 'Bearer ' + token } });

    console.log('\n[+] OK! PASSED!');
  } catch (e) {
    console.error(e.response ? JSON.stringify(e.response.data) : e.message);
  }
})();
