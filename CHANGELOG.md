# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.1.0](https://github.com/BBBaden/json-backend/releases/tag/v1.1.0) - 2024-12-11

### Added

- Validate data and accounts file (#5)

## [1.0.1](https://github.com/BBBaden/json-backend/releases/tag/v1.0.1) - 2024-11-17

### Fixed

- Support authorization header with CORS requests (#4)

## [1.0.0](https://github.com/BBBaden/json-backend/releases/tag/v1.0.0) - 2024-08-26

Initial release.

### Added

- API endpoint: GET /data/:collection
- API endpoint: GET /data/:collection/:id
- API endpoint: POST /data/:collection
- API endpoint: PUT /data/:collection/:id
- API endpoint: DELETE /data/:collection/:id
- API endpoint: POST /auth/register
- API endpoint: POST /auth/signin
- API endpoint: POST /auth/changepassword
- API endpoint: POST /auth/refresh
- API endpoint: DELETE /auth/account/:id
- Configuration through command line and/or environment
- Logging
