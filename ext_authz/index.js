const grpc = require('@grpc/grpc-js');
const protoLoader = require('@grpc/proto-loader');
const config = require('./src/config');
const { verifyAccessToken } = require('./src/tokenVerify');
const { verifyDPoP } = require('./src/dpopVerify');
const { verifyMTLSBinding } = require('./src/certUtils');

const PROTO_PATH = __dirname + '/protos/envoy-api/envoy/service/auth/v3/external_auth.proto';

const packageDefinition = protoLoader.loadSync(PROTO_PATH, {
  keepCase: true,
  longs: String,
  enums: String,
  defaults: true,
  oneofs: true,
  includeDirs: [
    __dirname + '/protos/envoy-api',
    __dirname + '/protos/googleapis',
    __dirname + '/protos/xds',
    __dirname + '/protos/protoc-gen-validate'
  ]
});

const envoyProto = grpc.loadPackageDefinition(packageDefinition).envoy.service.auth.v3;

async function check(call, callback) {
  console.log("---[EXT-AUTHZ-GRPC]--- Received request from Envoy!");
  
  // Extract header from origin request that Envoy processed
  const httpAttrs = call.request.attributes.request.http;
  const headers = httpAttrs.headers;
  
  const authHeader = headers['authorization'];
  const dpopHeader = headers['dpop'];
  const certHeader = headers['x-forwarded-client-cert'];

  try {
    if (!authHeader) throw new Error("Missing Authorization header");

    const token = authHeader.replace('DPoP ', '').replace('Bearer ', '');
    const payload = await verifyAccessToken(token);

    if (authHeader.startsWith('DPoP')) {
      // Regenerate URL to verify DPoP
      const scheme = headers['x-forwarded-proto'] || 'https';
      const host = headers['host'] || headers[':authority'];
      const fullUrl = `${scheme}://${host}${httpAttrs.path}`;
      
      await verifyDPoP(dpopHeader, payload, httpAttrs.method, fullUrl);
    } else {
      verifyMTLSBinding(certHeader, payload);
    }

    console.log(`---[Success]---\n Authorized: ${payload.sub}`);
    
    callback(null, {
      status: { code: grpc.status.OK },
      ok_response: {
        headers: [{ header: { key: 'x-auth-user', value: payload.sub } }]
      }
    });

  } catch (error) {
    console.error(`---[Forbidden]---\n ${error.message}`);
    
    // Envoy (PERMISSION_DENIED)
    callback(null, {
      status: { code: grpc.status.PERMISSION_DENIED },
      denied_response: {
        status: { code: grpc.status.PERMISSION_DENIED },
        body: error.message
      }
    });
  }
}

// Initialize & run gRPC Server
const server = new grpc.Server();
server.addService(envoyProto.Authorization.service, { Check: check });

server.bindAsync(`0.0.0.0:${config.PORT}`, grpc.ServerCredentials.createInsecure(), (error, port) => {
  if (error) {
    console.error(error);
    return;
  }
  console.log(`gRPC Ext_Authz Service running on port ${port}`);
  server.start();
});