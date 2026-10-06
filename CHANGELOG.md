# Changelog

All notable changes to this project are documented in this file.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this
project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `dns-muumuu` authenticator that solves `dns-01` challenges with the Muumuu Domain API v2.
- Zone discovery for sub-domains and multi-label TLDs.
- Cleanup that deletes only the record created by the run, falling back to a value match.
- Retries for rate limiting and maintenance (`Retry-After` on 429/503), transient server errors
  and network errors.
- Validation of the credentials file (token prefix, https endpoint, sandbox token).
- Validation of API responses, so unexpected shapes surface as Certbot errors.
- One domain lookup and nameserver check per registered domain, however many names it covers.
