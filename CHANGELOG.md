# Changelog

## [v0.1.0](https://github.com/kenchan/certbot-dns-muumuu/commits/v0.1.0) - 2026-10-06

First release.

### Added

- `dns-muumuu` authenticator that solves `dns-01` challenges with the Muumuu Domain API v2.
- Zone discovery for sub-domains and multi-label TLDs.
- Cleanup that deletes only the record created by the run, falling back to a value match.
- Retries for rate limiting and maintenance (`Retry-After` on 429/503), transient server errors
  and network errors.
- Validation of the credentials file (token prefix, https endpoint, sandbox token).
- Validation of API responses, so unexpected shapes surface as Certbot errors.
- One domain lookup and nameserver check per registered domain, however many names it covers.
