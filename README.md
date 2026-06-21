# Zero-Trust API Authentication

This repository implements a zero-trust API authentication prototype using mutual TLS (mTLS) for machine-to-machine authentication and DPoP/PoP for user-bound token proof-of-possession. It demonstrates end-to-end certificate lifecycle management, key rotation, and token verification using Envoy as an external authorization (ext_authz) filter.

Table of Contents
- Overview
- Features
- Architecture
- Repository layout
- Prerequisites
- Quickstart
- Configuration
- Development
- Testing
- Security notes
- Contributing
- License

Overview
--------
This project shows how to enforce zero-trust principles at the API gateway layer by combining:

- mTLS for strong, PKI-backed machine identity.
- DPoP (Demonstration of Proof-of-Possession) and PoP token verification for user-bound access tokens.
- Envoy as a proxy that delegates policy checks to an external authorization service (`ext_authz`).

The reference implementation includes the Envoy configuration, an external authorization service, helper scripts for generating certificates, and example infrastructure manifests.

Features
--------
- mTLS-based machine identity and secure channel establishment.
- DPoP/PoP verification for user-bound access tokens.
- Certificate issuance and revocation examples (demo CA files in `infra/demoCA`).
- Envoy `ext_authz` integration with a Node.js external authorizer (`ext_authz/`).
- Example Docker and Kubernetes manifests for local and cluster-based testing.

Architecture
------------
At a high level:

- Envoy terminates TLS and performs mTLS authentication for upstream clients.
- Envoy forwards requests to `ext_authz` for token verification and authorization decisions.
- `ext_authz` verifies DPoP signatures and validates token claims and certificate binding.

Repository layout
-----------------
- `ext_authz/` — External authorization service implementation (Node.js).
- `infra/` — Infrastructure utilities and certificate material for the demo CA and test scripts.
- `envoy-config/` — Envoy configuration and deployment manifests.
- `clients/` — Example clients and helper scripts for obtaining tokens and making requests.
- `docs/` — Design notes and usage documentation.
- `tests/` — Test cases and verification scripts.

Prerequisites
-------------
- Docker and Docker Compose (for quick local deployments).
- Node.js 14+ (for running the external authorizer locally).
- OpenSSL (for certificate generation when using the demo CA).

Quickstart (local, Docker Compose)
---------------------------------
1. From the repository root, build and start services with Docker Compose:

```bash
docker compose -f infra/docker-compose.yml up --build -d
```

2. Verify Envoy and the `ext_authz` service are running, then use the provided client scripts in `clients/` to obtain a DPoP-bound token and make requests.

Configuration
-------------
- Envoy configuration files are in `envoy-config/` and `infra/` (sample `envoy_real_config.json`).
- The external authorizer source is in `ext_authz/` and reads configuration from `ext_authz/config.js` and environment variables.
- Certificate authority and demo certificates live in `infra/demoCA/` and `infra/certs/`. Follow the scripts in `infra/` to recreate test certificates.

Development
-----------
- To run the external authorizer locally:

```bash
cd ext_authz
npm install
node index.js
```

- To iterate on Envoy configuration, modify files in `envoy-config/` and reload Envoy according to your deployment method.

Testing
-------
- Unit and integration tests (where present) are located in `tests/`.
- Use `infra/loadtest.js` and `infra/stress_test.js` for basic performance demonstrations.

Security notes
--------------
- This repository is a reference/demo implementation. Do not reuse demo CA material in production.
- Rotate keys and revoke certificates according to your security policy.
- Validate token lifetimes, nonce usage, and replay protections when implementing DPoP.

Contributing
------------
Contributions are welcome. Please open issues for bugs or feature requests and submit pull requests with clear descriptions and tests where appropriate.

License
-------
See the `LICENSE` file at the repository root for licensing details.
.

