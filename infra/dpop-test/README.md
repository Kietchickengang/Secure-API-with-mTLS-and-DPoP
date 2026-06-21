# GUIDE FOR TESTING

## Environment Setup

**1. `VALID_TOKEN`**

```sh
export VALID_TOKEN=$(node -e "const fs = require('fs'); const { generateKeyPair, SignJWT, exportJWK, calculateJwkThumbprint } = require('jose'); const axios = require('axios'); const https = require('https'); const crypto = require('crypto'); (async () => {
  const { publicKey, privateKey } = await generateKeyPair('ES256');
  const privateJwk = await exportJWK(privateKey);
  fs.writeFileSync('my-dpop-key.json', JSON.stringify(privateJwk));
  const jwk = await exportJWK(publicKey);
  const jkt = await calculateJwkThumbprint(jwk);
  const dpopT = await new SignJWT({ htm: 'POST', htu: 'https://localhost:8443/realms/zero-trust-realm/protocol/openid-connect/token', jti: crypto.randomBytes(16).toString('hex') }).setProtectedHeader({ alg: 'ES256', jwk, typ: 'dpop+jwt' }).setIssuedAt().sign(privateKey);
  const res = await axios.post('https://localhost:8443/realms/zero-trust-realm/protocol/openid-connect/token', new URLSearchParams({ grant_type: 'client_credentials', client_id: 'api-gatewate-client', client_secret: 'Cf18q68tal79D5sQ8bVRnNSLV4roRFr3', dpop_jkt: jkt }), { headers: { 'DPoP': dpopT }, httpsAgent: new https.Agent({ rejectUnauthorized: false }) });
  console.log(res.data.access_token);
})()")
```

**2. `VALID_DPOP`**

```sh
export VALID_DPOP=$(node -e "const fs = require('fs'); const crypto = require('crypto'); const { importJWK, SignJWT } = require('jose'); (async () => {
  const privateJwk = JSON.parse(fs.readFileSync('my-dpop-key.json'));
  const privateKey = await importJWK(privateJwk, 'ES256');
  const { d, ...publicJwk } = privateJwk;
  const ath = crypto.createHash('sha256').update(process.env.VALID_TOKEN).digest('base64url');
  const dpop = await new SignJWT({ htm: 'GET', htu: 'https://192.168.49.2:31646/headers', jti: crypto.randomBytes(16).toString('hex'), ath }).setProtectedHeader({ alg: 'ES256', jwk: publicJwk, typ: 'dpop+jwt' }).setIssuedAt().sign(privateKey);
  console.log(dpop);
})()")
```

**3. `HACKER_DPOP`**

```sh
export HACKER_DPOP=$(node -e "const { generateKeyPair, SignJWT, exportJWK } = require('jose'); const crypto = require('crypto'); (async () => {
  const { publicKey, privateKey } = await generateKeyPair('ES256');
  const jwk = await exportJWK(publicKey);
  const ath = crypto.createHash('sha256').update(process.env.VALID_TOKEN).digest('base64url');
  const dpop = await new SignJWT({ htm: 'GET', htu: 'https://192.168.49.2:31646/headers', jti: crypto.randomBytes(16).toString('hex'), ath }).setProtectedHeader({ alg: 'ES256', jwk, typ: 'dpop+jwt' }).setIssuedAt().sign(privateKey);
  console.log(dpop);
})()")
```

**4. `WRONG_URL_DPOP`**

```sh
export WRONG_URL_DPOP=$(node -e "const fs = require('fs'); const crypto = require('crypto'); const { importJWK, SignJWT } = require('jose'); (async () => { const privateJwk = JSON.parse(fs.readFileSync('my-dpop-key.json')); const privateKey = await importJWK(privateJwk, 'ES256'); const { d, ...publicJwk } = privateJwk; const ath = crypto.createHash('sha256').update(process.env.VALID_TOKEN).digest('base64url'); const dpop = await new SignJWT({ htm: 'GET', htu: 'https://192.168.49.2:31646/xHelper', jti: crypto.randomBytes(16).toString('hex'), ath }).setProtectedHeader({ alg: 'ES256', jwk: publicJwk, typ: 'dpop+jwt' }).setIssuedAt().sign(privateKey); console.log(dpop); })()")
```

**5. `WRONG_ATH_DPOP`**

```sh
export WRONG_ATH_DPOP=$(node -e "const fs = require('fs'); const crypto = require('crypto'); const { importJWK, SignJWT } = require('jose'); (async () => { const privateJwk = JSON.parse(fs.readFileSync('my-dpop-key.json')); const privateKey = await importJWK(privateJwk, 'ES256'); const { d, ...publicJwk } = privateJwk; const ath = crypto.createHash('sha256').update('HEHE_NO_ONE_KNOWS_I_FAKED_IT_:>').digest('base64url'); const dpop = await new SignJWT({ htm: 'GET', htu: 'https://192.168.49.2:31646/headers', jti: crypto.randomBytes(16).toString('hex'), ath }).setProtectedHeader({ alg: 'ES256', jwk: publicJwk, typ: 'dpop+jwt' }).setIssuedAt().sign(privateKey); console.log(dpop); })()")
```

---

## Test Cases

**TC-01 — Happy Path**

```sh
curl -X GET https://192.168.49.2:31646/headers \
  --cert valid-client.crt --key valid-client.key --cacert vault-ca.crt \
  -H "Authorization: DPoP $VALID_TOKEN" -H "DPoP: $VALID_DPOP" -k
```

**TC-02 — Have Token but No Proof**

```sh
curl -X GET https://192.168.49.2:31646/headers \
  --cert valid-client.crt --key valid-client.key --cacert vault-ca.crt \
  -H "Authorization: DPoP $VALID_TOKEN" -H "DPoP: $HACKER_DPOP" -k
```

**TC-03 — Replay Attack**

```sh
curl -X GET https://192.168.49.2:31646/headers \
  --cert valid-client.crt --key valid-client.key --cacert vault-ca.crt \
  -H "Authorization: DPoP $VALID_TOKEN" -H "DPoP: $VALID_DPOP" -k
```

**TC-04 — No Cert for mTLS**

```sh
curl -X GET https://192.168.49.2:31646/headers \
  -H "Authorization: DPoP $VALID_TOKEN" -H "DPoP: $VALID_DPOP" -k
```

**TC-05 — Fake Cert**

```sh
openssl req -x509 -newkey rsa:2048 -keyout fake.key -out fake.crt -days 1 -nodes -subj "/CN=hacker"

curl -X GET https://192.168.49.2:31646/headers \
  --cert fake.crt --key fake.key \
  -H "Authorization: DPoP $VALID_TOKEN" -H "DPoP: $VALID_DPOP" -k
```

**TC-06 — Token Tampering**

```sh
curl -X GET https://192.168.49.2:31646/headers \
  --cert valid-client.crt --key valid-client.key --cacert vault-ca.crt \
  -H "Authorization: DPoP ${VALID_TOKEN}_1_H4CK3D_U_<3" -H "DPoP: $VALID_DPOP" -k
```

**TC-07 — Wrong HTM / HTU**

```sh
curl -X GET https://192.168.49.2:31646/benign-app \
  --cert valid-client.crt --key valid-client.key --cacert vault-ca.crt \
  -H "Authorization: DPoP $VALID_TOKEN" -H "DPoP: $WRONG_URL_DPOP" -k
```

**TC-08 — Cross-Token Attack (ath mismatch)**

```sh
curl -X GET https://192.168.49.2:31646/headers \
  --cert valid-client.crt --key valid-client.key --cacert vault-ca.crt \
  -H "Authorization: DPoP $VALID_TOKEN" -H "DPoP: $WRONG_ATH_DPOP" -k
```

**TC-09 — Expired Proof**

```sh
curl -X GET https://192.168.49.2:31646/headers \
  --cert valid-client.crt --key valid-client.key --cacert vault-ca.crt \
  -H "Authorization: DPoP $VALID_TOKEN" -H "DPoP: $VALID_DPOP" -k
```
**TC-10 - Future-dated proof**

```sh
curl -X GET https://192.168.49.2:31646/headers \
  --cert valid-client.crt --key valid-client.key --cacert vault-ca.crt \
  -H "Authorization: DPoP $VALID_TOKEN" -H "DPoP: $FUTURE_DPOP" -k
```