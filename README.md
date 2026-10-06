# certbot-dns-muumuu

A [Certbot](https://certbot.eff.org/) DNS Authenticator plugin for
[Muumuu Domain](https://muumuu-domain.com/) (ムームードメイン). It completes ACME `dns-01`
challenges by creating, and then removing, `_acme-challenge` TXT records through the
[Muumuu Domain API v2](https://muumuu-domain.com/developers/).

With `dns-01` you can obtain wildcard certificates (`*.example.com`) and certificates for hosts
that are not reachable from the Internet.

## Requirements

- Python 3.10 or later and Certbot 4.0 or later
- A domain registered at Muumuu Domain whose nameservers are set to **Muumuu DNS**
  (ムームーDNS, API `setup-type` `muumuu_dns`)
- A Muumuu Domain Personal Access Token (PAT) with the `domains:read`, `dns:read` and
  `dns:write` scopes

## Installation

Install the plugin into the same Python environment as Certbot:

```sh
pip install git+https://github.com/kenchan/certbot-dns-muumuu.git
```

If Certbot is installed with snap or Docker, the plugin has to be installed into that
environment instead (e.g. build a Docker image `FROM certbot/certbot` that runs the command
above).

Check that Certbot sees the plugin:

```sh
certbot plugins
# * dns-muumuu
# Description: Obtain certificates using a DNS TXT record (if you are using Muumuu DNS for DNS).
```

## Issuing a Personal Access Token

Issue a PAT from the Muumuu Domain developer portal / control panel
(<https://muumuu-domain.com/developers/>) with these scopes:

| Scope          | Used for                                                       |
| -------------- | -------------------------------------------------------------- |
| `domains:read` | Finding the registered domain (`GET /me/domains?fqdn=...`)     |
| `dns:read`     | Reading the nameserver setting and listing TXT records         |
| `dns:write`    | Creating and deleting the `_acme-challenge` TXT records        |

A token with `dns:write` can modify every DNS record of every domain in the account, so treat it
like your account password. Certbot renews certificates unattended, so pick an expiry that
outlives your renewal schedule (or none) and rotate it deliberately.

## Credentials file

```ini
# ~/.secrets/certbot/muumuu.ini
dns_muumuu_token = muu_pat_0123456789abcdef

# Optional: API endpoint, defaults to https://muumuu-domain.com/api/v2
# dns_muumuu_endpoint = https://api-sandbox.muumuu-domain.com/api/v2
```

Restrict access to it; Certbot warns when the file is readable by other users:

```sh
chmod 600 ~/.secrets/certbot/muumuu.ini
```

Certbot stores the path to this file (not its contents) in the renewal configuration, so keep it
in place for renewals.

## Usage

```sh
certbot certonly \
  --authenticator dns-muumuu \
  --dns-muumuu-credentials ~/.secrets/certbot/muumuu.ini \
  -d example.com \
  -d '*.example.com'
```

| Option                               | Description                                                                 |
| ------------------------------------ | --------------------------------------------------------------------------- |
| `--dns-muumuu-credentials`           | Path to the credentials INI file (required)                                 |
| `--dns-muumuu-propagation-seconds`   | Seconds to wait before asking the ACME server to validate (default: `30`)   |

Sub-domains and multi-label TLDs work as expected: for `-d www.example.co.jp` the plugin tries
`www.example.co.jp`, `example.co.jp`, `co.jp`, ... against the domains in your account and uses
the first exact match.

## How it works

1. Find the domain ID (`MU` + 8 digits) with `GET /me/domains?fqdn=<candidate>`.
2. Check `GET /me/domains/{id}/nameservers` and log a warning when `setup-type` is not
   `muumuu_dns`.
3. Create the record with `POST /me/domains/{id}/dns-records`
   (`{"fqdn": "_acme-challenge.example.com", "type": "TXT", "value": "<token>"}`).
   If an identical record already exists (HTTP 409, e.g. after an interrupted run), it is reused.
4. Wait `--dns-muumuu-propagation-seconds`, then let the ACME server validate.
5. Delete exactly the record created in step 3 with `DELETE /me/domains/{id}/dns-records/{record-id}`.
   If its ID is unknown, the TXT records of that name are listed and only the one whose value
   equals the validation token is deleted. Other records are never touched, and cleanup failures
   are logged instead of aborting Certbot.

HTTP 429 responses are retried up to 3 times, honouring `Retry-After` (up to 300 seconds).
HTTP 401/403 errors are reported with a hint about the token and its scopes.

## Behaviour verified against the production API

The following was checked on 2026-10-06 by creating and deleting `_acme-challenge` TXT records
on a real domain with the production API and querying `dns01.muumuu-domain.com` /
`dns02.muumuu-domain.com` directly:

- **Multiple TXT records with the same name coexist.** Two records with the same `fqdn` and
  different values were both created (HTTP 201) and both served, so `example.com` and
  `*.example.com` can be validated in the same run.
- **Exact duplicates are rejected** with HTTP 409 `conflict`
  ("A record with the same fqdn, type, and value already exists").
- **TXT values are returned unquoted** (e.g. `did=did:plc:...`) and `fqdn` is returned with a
  trailing dot. The `fqdn` filter on `GET .../dns-records` accepts it with or without the dot.
- **Deleting a missing record returns HTTP 404**, which the plugin treats as already deleted.
- **Propagation:** new records were answered authoritatively by both Muumuu DNS servers within
  about 2 seconds. The default of 30 seconds leaves a wide margin for slower updates; raise
  `--dns-muumuu-propagation-seconds` if validation fails with "no TXT record found".
- **End-to-end issuance:** a certificate for `example.com` + `*.example.com` (a `.com` domain
  delegated to Muumuu DNS) was issued from the Let's Encrypt staging environment with the default
  settings, and `certbot renew --dry-run` succeeded. Both challenge records were removed
  afterwards.

## Limitations

- **The nameservers must be Muumuu DNS.** The API stores records for a domain regardless of its
  nameserver setting, but they are only visible on the public DNS when the domain is delegated to
  Muumuu DNS. Other settings (`custom`, `acquired_domain`, `lolipop`, `parking`, ...) only cause a
  warning, because some of them may still point at Muumuu DNS; validation will fail if they don't.
- **TTL is fixed at 3600 seconds** by the API and cannot be changed.
- **At most 200 records per domain** (excluding SOA). Creating a record beyond that fails with
  "Record limit exceeded".
- **Rate limit:** 1,000 authenticated requests per hour.

## Development

```sh
uv sync
uv run pytest
uv run ruff check .
uv run ruff format --check .
uv run mypy
uv build
```

## License

Apache License 2.0. See [LICENSE](LICENSE).
