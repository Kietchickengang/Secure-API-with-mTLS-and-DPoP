module.exports = {
  PORT: 50051,
  JWKS_URL: 'https://host.minikube.internal:8443/realms/zero-trust-realm/protocol/openid-connect/certs',
  ISSUER: "https://localhost:8443/realms/zero-trust-realm",
  
  // Redis container address
  REDIS_HOST: process.env.REDIS_HOST || 'redis-master', 
  REDIS_PORT: 6379
};