import http from 'k6/http';
import { check, sleep } from 'k6';

const certFile = open('./valid-client.crt');
const keyFile = open('./valid-client.key');

const ACCESS_TOKEN = __ENV.VALID_TOKEN;
const DPOP_PROOF = __ENV.DPOP_TYPE ? __ENV[__ENV.DPOP_TYPE] : __ENV.VALID_DPOP;

export let options = {
    vus: 1, 
    iterations: 1, 
    
    tlsAuth: [
        {
            domains: ['192.168.49.2'],
            cert: certFile,
            key: keyFile,
        },
    ],
    insecureSkipTLSVerify: true,
};

export default function () {
    if (!ACCESS_TOKEN || !DPOP_PROOF) {
        console.error("Run source init_env.sh first.");
        return;
    }

    const url = 'https://192.168.49.2:31646/headers';
    const params = {
        headers: {
            'Authorization': `DPoP ${ACCESS_TOKEN}`,
            'DPoP': DPOP_PROOF,
        },
    };

    let res = http.get(url, params);
    console.log(`[Test ${__ENV.DPOP_TYPE || 'VALID_DPOP'}] Status: ${res.status} | Body: ${res.body}`);

    check(res, {
        'Status matches expectation': (r) => r.status === (__ENV.EXPECTED_STATUS ? 
            parseInt(__ENV.EXPECTED_STATUS) : 200),
    });
}