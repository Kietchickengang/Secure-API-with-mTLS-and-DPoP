import http from 'k6/http';
import { check } from 'k6';

const certFile = open('./valid-client.crt');
const keyFile = open('./valid-client.key');

const ACCESS_TOKEN = __ENV.VALID_TOKEN;
const DPOP_PROOF = __ENV.VALID_DPOP;
export let options = {
    vus: 50,           
    duration: '30s',
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
    const url = 'https://192.168.49.2:31646/headers';
    const params = {
        headers: {
            'Authorization': `DPoP ${ACCESS_TOKEN}`,
            'DPoP': DPOP_PROOF,
        },
    };
    let res = http.get(url, params);
    check(res, {
        'Status is 200': (r) => r.status === 200,
    });
}