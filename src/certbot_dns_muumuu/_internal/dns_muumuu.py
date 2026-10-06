"""DNS Authenticator for Muumuu Domain."""

import logging
import time
from collections.abc import Callable
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from importlib.metadata import PackageNotFoundError, version
from typing import Any
from urllib.parse import urlsplit

import requests
from certbot import errors
from certbot.plugins import dns_common
from certbot.plugins.dns_common import CredentialsConfiguration

logger = logging.getLogger(__name__)

DEFAULT_ENDPOINT = "https://muumuu-domain.com/api/v2"
SANDBOX_ENDPOINT = "https://api-sandbox.muumuu-domain.com/api/v2"
TOKEN_PREFIX = "muu_pat_"
SANDBOX_TOKEN_PREFIX = "muu_pat_sandbox_"
REQUIRED_SCOPES = ("domains:read", "dns:read", "dns:write")
MUUMUU_DNS_SETUP_TYPE = "muumuu_dns"


def _user_agent() -> str:
    try:
        return f"certbot-dns-muumuu/{version('certbot-dns-muumuu')}"
    except PackageNotFoundError:  # pragma: no cover
        return "certbot-dns-muumuu"


class Authenticator(dns_common.DNSAuthenticator):
    """DNS Authenticator for Muumuu Domain

    This Authenticator uses the Muumuu Domain API v2 to fulfill a dns-01 challenge.
    """

    description = (
        "Obtain certificates using a DNS TXT record (if you are using Muumuu DNS for DNS)."
    )

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.credentials: CredentialsConfiguration | None = None
        self._client: _MuumuuClient | None = None
        self._domain_ids: dict[str, str] = {}
        self._record_ids: dict[tuple[str, str], int] = {}

    @classmethod
    def add_parser_arguments(
        cls, add: Callable[..., None], default_propagation_seconds: int = 30
    ) -> None:
        super().add_parser_arguments(add, default_propagation_seconds)
        add("credentials", help="Muumuu Domain credentials INI file.")

    def more_info(self) -> str:
        return (
            "This plugin configures a DNS TXT record to respond to a dns-01 challenge using "
            "the Muumuu Domain API v2."
        )

    def _setup_credentials(self) -> None:
        self.credentials = self._configure_credentials(
            "credentials",
            "Muumuu Domain credentials INI file",
            {
                "token": "Personal Access Token for the Muumuu Domain API "
                f"(scopes: {', '.join(REQUIRED_SCOPES)})",
            },
            self._validate_credentials,
        )

    @staticmethod
    def _validate_credentials(credentials: CredentialsConfiguration) -> None:
        filename = credentials.confobj.filename
        token = credentials.conf("token") or ""
        if not token.startswith(TOKEN_PREFIX):
            raise errors.PluginError(
                f"{filename}: dns_muumuu_token does not look like a Muumuu Domain Personal "
                f"Access Token (it should start with {TOKEN_PREFIX})."
            )

        endpoint = credentials.conf("endpoint")
        if endpoint:
            url = urlsplit(endpoint)
            if url.scheme != "https" or not url.netloc:
                raise errors.PluginError(
                    f"{filename}: dns_muumuu_endpoint must be an https:// URL "
                    f"(e.g. {SANDBOX_ENDPOINT}), got {endpoint!r}."
                )
        elif token.startswith(SANDBOX_TOKEN_PREFIX):
            raise errors.PluginError(
                f"{filename}: dns_muumuu_token is a sandbox token, which the production API "
                f"rejects. Set dns_muumuu_endpoint = {SANDBOX_ENDPOINT} to use the sandbox, "
                "or use a production token."
            )

    def _perform(self, domain: str, validation_name: str, validation: str) -> None:
        client = self._get_client()
        domain_id = self._find_domain_id(client, domain)
        self._record_ids[(validation_name, validation)] = client.add_txt_record(
            domain_id, validation_name, validation
        )

    def _cleanup(self, domain: str, validation_name: str, validation: str) -> None:
        domain_id = self._domain_ids.get(domain)
        if domain_id is None:
            logger.debug("No TXT record was created for %s; nothing to clean up.", domain)
            return

        try:
            client = self._get_client()
            record_id = self._record_ids.pop((validation_name, validation), None)
            if record_id is None:
                record_ids = client.find_txt_record_ids(domain_id, validation_name, validation)
            else:
                record_ids = [record_id]
            if not record_ids:
                logger.debug("TXT record for %s not found; no cleanup needed.", validation_name)
            for rid in record_ids:
                client.delete_record(domain_id, rid)
        except errors.PluginError as e:
            logger.warning(
                "Encountered error deleting TXT record %s for %s: %s", validation_name, domain, e
            )

    def _find_domain_id(self, client: "_MuumuuClient", domain: str) -> str:
        if domain not in self._domain_ids:
            domain_id, zone = client.find_domain(domain)
            self._warn_unless_muumuu_dns(client, domain_id, zone)
            self._domain_ids[domain] = domain_id
        return self._domain_ids[domain]

    @staticmethod
    def _warn_unless_muumuu_dns(client: "_MuumuuClient", domain_id: str, zone: str) -> None:
        # Why not fail here: the API accepts record changes regardless of the nameserver
        # setting, and nameservers such as "custom" ones may still point to Muumuu DNS.
        settings = client.get_nameserver_settings(domain_id)
        if settings.get("setup-type") != MUUMUU_DNS_SETUP_TYPE:
            logger.warning(
                "The nameservers of %s are not set to Muumuu DNS (setup-type: %s, "
                "nameservers: %s). TXT records created through the API are only visible on "
                "the public DNS when the domain uses Muumuu DNS, so validation will likely fail.",
                zone,
                settings.get("setup-type"),
                ", ".join(settings.get("nameservers") or []) or "none",
            )

    def _get_client(self) -> "_MuumuuClient":
        if self._client is None:
            if not self.credentials:  # pragma: no cover
                raise errors.Error("Plugin has not been prepared.")
            token = self.credentials.conf("token")
            assert token is not None
            endpoint = self.credentials.conf("endpoint") or DEFAULT_ENDPOINT
            self._client = _MuumuuClient(token, endpoint)
        return self._client


class _MuumuuClient:
    """Encapsulates all communication with the Muumuu Domain API v2."""

    page_size = 100
    max_attempts = 3
    max_retry_after = 300
    timeout = 30
    retryable_statuses = frozenset({429, 500, 502, 503, 504})

    def __init__(
        self,
        token: str,
        endpoint: str = DEFAULT_ENDPOINT,
        session: requests.Session | None = None,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self.endpoint = endpoint.rstrip("/")
        self.session = session or requests.Session()
        self.session.headers.update(
            {
                "Authorization": f"Bearer {token}",
                "Accept": "application/json",
                "User-Agent": _user_agent(),
            }
        )
        self._sleep = sleep

    def find_domain(self, domain: str) -> tuple[str, str]:
        """Find the domain registered in the account that is the zone for ``domain``.

        :param str domain: The domain (or any sub-domain of it) to look up.
        :returns: The domain ID (e.g. ``MU00000001``) and the FQDN of the registered domain.
        :raises certbot.errors.PluginError: if no registered domain matches.
        """
        # Why not query bare TLDs such as "com": the API rejects them with 400.
        guesses = [g for g in dns_common.base_domain_name_guesses(domain) if "." in g]
        for guess in guesses:
            try:
                body = self._request("GET", "/me/domains", params={"fqdn": guess})
            except _ApiError as e:
                if e.status_code != 400:
                    raise
                logger.debug("Skipping %s, which the API does not accept: %s", guess, e)
                continue
            for item in body.get("data", []):
                if _normalize(item.get("fqdn", "")) == _normalize(guess):
                    logger.debug("Found domain %s (%s) for %s", item["fqdn"], item["id"], domain)
                    return item["id"], item["fqdn"]
        raise errors.PluginError(
            f"Unable to find a Muumuu Domain domain for {domain} (tried: {', '.join(guesses)}). "
            "Make sure the domain belongs to the account that issued the token."
        )

    def get_nameserver_settings(self, domain_id: str) -> dict[str, Any]:
        """Return the nameserver settings (``setup-type`` and ``nameservers``) of a domain."""
        body = self._request("GET", f"/me/domains/{domain_id}/nameservers")
        data: dict[str, Any] = body.get("data", {})
        return data

    def add_txt_record(self, domain_id: str, record_name: str, record_content: str) -> int:
        """Create a TXT record and return its ID.

        If an identical record already exists (e.g. left over from an interrupted run, or created
        by a retried request whose response was lost), its ID is returned instead.

        :raises certbot.errors.PluginError: if the record cannot be created.
        """
        try:
            body = self._request(
                "POST",
                f"/me/domains/{domain_id}/dns-records",
                json={"fqdn": _normalize(record_name), "type": "TXT", "value": record_content},
            )
        except _ApiError as e:
            if e.status_code == 409:
                existing = self.find_txt_record_ids(domain_id, record_name, record_content)
                if existing:
                    logger.debug("TXT record for %s already exists (id %s)", record_name, existing)
                    return existing[0]
            raise errors.PluginError(f"Unable to add TXT record for {record_name}: {e}") from e
        record_id: int = body["data"]["id"]
        logger.debug("Created TXT record %s for %s", record_id, record_name)
        return record_id

    def find_txt_record_ids(
        self, domain_id: str, record_name: str, record_content: str
    ) -> list[int]:
        """Return the IDs of the TXT records named ``record_name`` whose value is
        ``record_content``."""
        return [
            record["id"]
            for record in self._list_txt_records(domain_id, record_name)
            if _normalize(record.get("fqdn", "")) == _normalize(record_name)
            and _unquote(record.get("value", "")) == record_content
        ]

    def delete_record(self, domain_id: str, record_id: int) -> None:
        """Delete a DNS record. A record that no longer exists is not an error."""
        try:
            self._request("DELETE", f"/me/domains/{domain_id}/dns-records/{record_id}")
        except _ApiError as e:
            if e.status_code != 404:
                raise
            logger.debug("TXT record %s was already deleted", record_id)
        else:
            logger.debug("Deleted TXT record %s", record_id)

    def _list_txt_records(self, domain_id: str, record_name: str) -> list[dict[str, Any]]:
        records: list[dict[str, Any]] = []
        page = 1
        while True:
            body = self._request(
                "GET",
                f"/me/domains/{domain_id}/dns-records",
                params={
                    "type": "TXT",
                    "fqdn": _normalize(record_name) + ".",
                    "page": page,
                    "page-size": self.page_size,
                },
            )
            data = body.get("data", [])
            records.extend(data)
            total = body.get("meta", {}).get("total", 0)
            if not data or len(records) >= total:
                return records
            page += 1

    def _request(self, method: str, path: str, **kwargs: Any) -> dict[str, Any]:
        # Why not retry only idempotent methods: a retried POST whose first attempt did create
        # the record gets 409, which add_txt_record resolves to the existing record.
        url = self.endpoint + path
        for attempt in range(1, self.max_attempts + 1):
            try:
                response = self.session.request(method, url, timeout=self.timeout, **kwargs)
            except (requests.ConnectionError, requests.Timeout) as e:
                if attempt == self.max_attempts:
                    raise errors.PluginError(
                        f"Network error communicating with the Muumuu Domain API "
                        f"({method} {path}): {e}"
                    ) from e
                wait = self._backoff(attempt)
                logger.info("Network error (%s); retrying in %d seconds", e, wait)
            except requests.RequestException as e:
                raise errors.PluginError(
                    f"Error communicating with the Muumuu Domain API ({method} {path}): {e}"
                ) from e
            else:
                if (
                    response.status_code not in self.retryable_statuses
                    or attempt == self.max_attempts
                ):
                    break
                if response.status_code == 429:
                    wait = _retry_after(response)
                else:
                    wait = self._backoff(attempt)
                if wait > self.max_retry_after:
                    break
                logger.info(
                    "Muumuu Domain API returned HTTP %d; retrying in %d seconds",
                    response.status_code,
                    wait,
                )
            self._sleep(wait)

        if response.status_code >= 400:
            raise _ApiError.from_response(response, f"{method} {path}")
        if response.status_code == 204 or not response.content:
            return {}
        try:
            result = response.json()
        except ValueError as e:
            raise errors.PluginError(
                f"Unexpected non-JSON response from the Muumuu Domain API ({method} {path}, "
                f"HTTP {response.status_code})"
            ) from e
        if not isinstance(result, dict):
            raise errors.PluginError(
                f"Unexpected response from the Muumuu Domain API ({method} {path}): {result!r}"
            )
        return result

    @staticmethod
    def _backoff(attempt: int) -> int:
        return int(2 ** (attempt - 1))


class _ApiError(errors.PluginError):
    def __init__(self, status_code: int, code: str, message: str, request: str = "") -> None:
        self.status_code = status_code
        self.code = code
        super().__init__(self._describe(status_code, code, message, request))

    @classmethod
    def from_response(cls, response: requests.Response, request: str = "") -> "_ApiError":
        try:
            error = response.json().get("error", {})
        except (ValueError, AttributeError):
            error = {}
        return cls(
            response.status_code,
            error.get("code", ""),
            error.get("message", "") or response.reason or "",
            request,
        )

    @staticmethod
    def _describe(status_code: int, code: str, message: str, request: str) -> str:
        detail = f"HTTP {status_code}" + (f" {code}" if code else "") + f": {message}"
        if request:
            detail += f" ({request})"
        if status_code == 401:
            return (
                f"{detail}. Check dns_muumuu_token in the credentials file; the token may "
                "have been revoked or have expired."
            )
        if status_code == 403:
            return (
                f"{detail}. Make sure the Personal Access Token has the "
                f"{', '.join(REQUIRED_SCOPES)} scopes."
            )
        if status_code == 429:
            return f"{detail}. The API rate limit was exceeded; try again later."
        return detail


def _normalize(fqdn: str) -> str:
    return fqdn.rstrip(".").lower()


def _unquote(value: str) -> str:
    # Why not compare as-is: the API returns TXT values unquoted today, but the zone file
    # representation is quoted and either form must match the validation token.
    if len(value) >= 2 and value[0] == value[-1] == '"':
        return value[1:-1]
    return value


def _retry_after(response: requests.Response) -> int:
    header = response.headers.get("Retry-After")
    if header is None:
        return 60
    try:
        return max(int(header), 1)
    except ValueError:
        pass
    try:
        when = parsedate_to_datetime(header)
    except (TypeError, ValueError):
        return 60
    if when.tzinfo is None:
        when = when.replace(tzinfo=timezone.utc)
    return max(int((when - datetime.now(timezone.utc)).total_seconds()), 1)
