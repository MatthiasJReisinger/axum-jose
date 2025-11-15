# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.2](https://github.com/MatthiasJReisinger/axum-jose/compare/v0.2.1...v0.2.2) - 2025-11-15

### Other

- *(deps)* Bump the axum group across 1 directory with 2 updates ([#13](https://github.com/MatthiasJReisinger/axum-jose/pull/13))
- *(deps)* Bump jsonwebtoken from 10.1.0 to 10.2.0 ([#11](https://github.com/MatthiasJReisinger/axum-jose/pull/11))
- *(deps)* Bump openssl from 0.10.74 to 0.10.75 ([#12](https://github.com/MatthiasJReisinger/axum-jose/pull/12))
- Add keywords and category slugs in Cargo.toml
- *(deps)* Bump tokio-util from 0.7.16 to 0.7.17 ([#10](https://github.com/MatthiasJReisinger/axum-jose/pull/10))

## [0.2.1](https://github.com/MatthiasJReisinger/axum-jose/compare/v0.2.0...v0.2.1) - 2025-11-02

### Other

- Fix formatting in crate docs
- Update Cargo.lock
- *(deps)* Bump jsonwebtoken from 9.3.1 to 10.1.0 ([#7](https://github.com/MatthiasJReisinger/axum-jose/pull/7))
- *(deps)* Bump reqwest from 0.12.23 to 0.12.24 ([#6](https://github.com/MatthiasJReisinger/axum-jose/pull/6))
- Configure dependabot group for tower crates
- Remove obsolete dependencies
- Increase dependabot's open pull request limit
- Configure dependabot group for axum crates
- *(deps)* Bump axum from 0.7.9 to 0.8.6 ([#3](https://github.com/MatthiasJReisinger/axum-jose/pull/3))
- *(deps)* Bump tokio from 1.47.1 to 1.48.0 ([#2](https://github.com/MatthiasJReisinger/axum-jose/pull/2))
- *(deps)* Bump openssl from 0.10.73 to 0.10.74 ([#4](https://github.com/MatthiasJReisinger/axum-jose/pull/4))
- *(deps)* Bump thiserror from 1.0.69 to 2.0.17 ([#5](https://github.com/MatthiasJReisinger/axum-jose/pull/5))
- *(deps)* Bump base64-url from 3.0.0 to 3.0.2 ([#1](https://github.com/MatthiasJReisinger/axum-jose/pull/1))
- Enable version updates via dependabot
- Add test for claim extraction
- Fix accident in crate docs
- Update release manual

## [0.2.0](https://github.com/MatthiasJReisinger/axum-jose/compare/v0.1.0...v0.2.0) - 2025-10-26

### Added

- Add support for more key algorithms

### Other

- Improve readme and crate docs

## [0.1.0](https://github.com/MatthiasJReisinger/axum-jose/releases/tag/v0.1.0) - 2025-10-11

### Added

- _(authorization)_ Enable use of jsonwebtoken::jwk::JwkSet
- Re-fetch if requested `kid` is not present in cached JWK set
- _(remote_jwk_set)_ Make caching configurable
- Introduce RemoteJwkSetBuilder to compose RemoteJwkSets
- Cache JWKs based on HTTP cache-control headers
- Add tower layer to enable use as axum middleware
- Add auth service

### Fixed

- Fix life-time issues in JwksCache by manually implementing Clone
- Respond with appropriate error code/message in case of unauthorized request

### Other

- Add project meta data to Cargo.toml
- Improve error names, remove obsolete variants, etc.
- Add formatting & linting stage
- Add minimal config for github actions
- Add git pre-push hook
- Address TODO
- Add documentation
- Rename crate to axum-jose
- Add minimal readme
- Add MIT License to the project
- _(authorization)_ Pass RemoteJwkSet in constructor
- Move authorization middleware into separate module
- Use BoxFuture instead of explicit pin box type
- Update Cargo.lock
- Implement JWK-set caching & rate limiting on top of tower
- Improve error handling
