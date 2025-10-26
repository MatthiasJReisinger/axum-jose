# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
