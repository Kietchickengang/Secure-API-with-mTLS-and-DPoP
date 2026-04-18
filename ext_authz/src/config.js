module.exports = {
  PORT: 50051,
  JWKS_URL: 'http://keycloak:8080/realms/myrealm/protocol/openid-connect/certs',
  ISSUER: 'http://keycloak:8080/realms/myrealm',
  
  // Redis container address
  REDIS_HOST: process.env.REDIS_HOST || 'localhost', 
  REDIS_PORT: 6379
};