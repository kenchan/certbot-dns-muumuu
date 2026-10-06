"""DNS Authenticator for Muumuu Domain."""

import logging
import time
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from importlib.metadata import PackageNotFoundError, version
from typing import Any
from urllib.parse import urlsplit

import requests
from certbot import achallenges, errors
from certbot.plugins import dns_common
from certbot.plugins.dns_common import CredentialsConfiguration

logger = logging.getLogger(__name__)

DEFAULT_ENDPOINT = "https://muumuu-domain.com/api/v2"
SANDBOX_ENDPOINT = "https://api-sandbox.muumuu-domain.com/api/v2"
TOKEN_PREFIX = "muu_pat_"
SANDBOX_TOKEN_PREFIX = "muu_pat_sandbox_"
REQUIRED_SCOPES = ("domains:read", "dns:read", "dns:write")
MUUMUU_DNS_SETUP_TYPE = "muumuu_dns"
DEFAULT_RETRY_AFTER = 60


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
        self._zone_ids: dict[str, str] = {}
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

    def cleanup(self, achalls: list[achallenges.AnnotatedChallenge]) -> None:
        try:
            super().cleanup(achalls)
        finally:
            if self._client is not None:
                self._client.close()
                self._client = None

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
        if endpoint and not _is_valid_endpoint(endpoint):
            raise errors.PluginError(
                f"{filename}: dns_muumuu_endpoint must be an https:// URL without a query or "
                f"fragment (e.g. {SANDBOX_ENDPOINT}), got {endpoint!r}."
            )

        if token.startswith(SANDBOX_TOKEN_PREFIX) and _hostname(
            endpoint or DEFAULT_ENDPOINT
        ) == _hostname(DEFAULT_ENDPOINT):
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

        client = self._get_client()
        record_id = self._record_ids.pop((validation_name, validation), None)
        if record_id is None:
            try:
                record_ids = client.find_txt_record_ids(domain_id, validation_name, validation)
            except errors.PluginError as e:
                logger.warning(
                    "Encountered error looking up TXT record %s for %s: %s",
                    validation_name,
                    domain,
                    e,
                )
                return
            if not record_ids:
                logger.debug("TXT record for %s not found; no cleanup needed.", validation_name)
        else:
            record_ids = [record_id]

        for rid in record_ids:
            try:
                client.delete_record(domain_id, rid)
            except errors.PluginError as e:
                logger.warning(
                    "Encountered error deleting TXT record %s (id %s) for %s: %s",
                    validation_name,
                    rid,
                    domain,
                    e,
                )

    def _find_domain_id(self, client: "_MuumuuClient", domain: str) -> str:
        if domain not in self._domain_ids:
            self._domain_ids[domain] = self._cached_zone_id(domain) or self._lookup_zone_id(
                client, domain
            )
        return self._domain_ids[domain]

    def _cached_zone_id(self, domain: str) -> str | None:
        for guess in dns_common.base_domain_name_guesses(domain):
            zone_id = self._zone_ids.get(_normalize(guess))
            if zone_id is not None:
                return zone_id
        return None

    def _lookup_zone_id(self, client: "_MuumuuClient", domain: str) -> str:
        zone = client.find_domain(domain)
        self._warn_unless_muumuu_dns(client, zone)
        self._zone_ids[_normalize(zone.fqdn)] = zone.id
        return zone.id

    @staticmethod
    def _warn_unless_muumuu_dns(client: "_MuumuuClient", zone: "_Domain") -> None:
        # Why not fail here: the API accepts record changes regardless of the nameserver
        # setting, and nameservers such as "custom" ones may still point to Muumuu DNS.
        try:
            settings = client.get_nameserver_settings(zone.id)
        except errors.PluginError as e:
            logger.debug("Could not check the nameservers of %s: %s", zone.fqdn, e)
            return
        if settings.setup_type != MUUMUU_DNS_SETUP_TYPE:
            logger.warning(
                "The nameservers of %s are not set to Muumuu DNS (setup-type: %s, "
                "nameservers: %s). TXT records created through the API are only visible on "
                "the public DNS when the domain uses Muumuu DNS, so validation will likely fail.",
                zone.fqdn,
                settings.setup_type,
                ", ".join(settings.nameservers) or "none",
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


@dataclass(frozen=True)
class _Domain:
    id: str
    fqdn: str


@dataclass(frozen=True)
class _NameserverSettings:
    setup_type: str
    nameservers: tuple[str, ...]


@dataclass(frozen=True)
class _TxtRecord:
    id: int
    fqdn: str
    value: str


class _MuumuuClient:
    """Encapsulates all communication with the Muumuu Domain API v2."""

    page_size = 100
    max_pages = 100
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

    def close(self) -> None:
        """Release the underlying HTTP connections."""
        self.session.close()

    def find_domain(self, domain: str) -> _Domain:
        """Find the domain registered in the account that is the zone for ``domain``.

        :param str domain: The domain (or any sub-domain of it) to look up.
        :returns: The registered domain.
        :raises certbot.errors.PluginError: if no registered domain matches.
        """
        # Why not query bare TLDs such as "com": the API rejects them with 400.
        guesses = [g for g in dns_common.base_domain_name_guesses(domain) if "." in g]
        for guess in guesses:
            try:
                for item in self._paginate("/me/domains", {"fqdn": guess}):
                    found = _parse_domain(item)
                    if _normalize(found.fqdn) == _normalize(guess):
                        logger.debug("Found domain %s (%s) for %s", found.fqdn, found.id, domain)
                        return found
            except _ApiError as e:
                if e.status_code != 400:
                    raise
                logger.debug("Skipping %s, which the API does not accept: %s", guess, e)
        raise errors.PluginError(
            f"Unable to find a Muumuu Domain domain for {domain} (tried: {', '.join(guesses)}). "
            "Make sure the domain belongs to the account that issued the token."
        )

    def get_nameserver_settings(self, domain_id: str) -> _NameserverSettings:
        """Return the nameserver settings (``setup-type`` and ``nameservers``) of a domain."""
        path = f"/me/domains/{domain_id}/nameservers"
        return _parse_nameserver_settings(_data(self._request("GET", path), path))

    def add_txt_record(self, domain_id: str, record_name: str, record_content: str) -> int:
        """Create a TXT record and return its ID.

        If an identical record already exists (e.g. left over from an interrupted run, or created
        by a retried request whose response was lost), its ID is returned instead.

        :raises certbot.errors.PluginError: if the record cannot be created.
        """
        path = f"/me/domains/{domain_id}/dns-records"
        try:
            body = self._request(
                "POST",
                path,
                json={"fqdn": _normalize(record_name), "type": "TXT", "value": record_content},
            )
        except _ApiError as e:
            if e.status_code == 409:
                existing = self.find_txt_record_ids(domain_id, record_name, record_content)
                if existing:
                    logger.debug("TXT record for %s already exists (id %s)", record_name, existing)
                    return existing[0]
            raise errors.PluginError(f"Unable to add TXT record for {record_name}: {e}") from e
        record = _parse_txt_record(_data(body, path))
        logger.debug("Created TXT record %s for %s", record.id, record_name)
        return record.id

    def find_txt_record_ids(
        self, domain_id: str, record_name: str, record_content: str
    ) -> list[int]:
        """Return the IDs of the TXT records named ``record_name`` whose value is
        ``record_content``."""
        params = {"type": "TXT", "fqdn": _normalize(record_name) + "."}
        records = (
            _parse_txt_record(item)
            for item in self._paginate(f"/me/domains/{domain_id}/dns-records", params)
        )
        return [
            record.id
            for record in records
            if _normalize(record.fqdn) == _normalize(record_name)
            and _unquote(record.value) == record_content
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

    def _paginate(self, path: str, params: dict[str, str]) -> Iterator[Any]:
        seen = 0
        for page in range(1, self.max_pages + 1):
            body = self._request(
                "GET", path, params={**params, "page": page, "page-size": self.page_size}
            )
            items = _data(body, path)
            if not isinstance(items, list):
                raise _UnexpectedResponseError(path, "data is not a list")
            yield from items
            seen += len(items)
            meta = _dict(body, path).get("meta")
            total = meta.get("total") if isinstance(meta, dict) else None
            if len(items) < self.page_size or (isinstance(total, int) and seen >= total):
                return
        logger.warning("Stopped reading %s after %d pages", path, self.max_pages)

    def _request(self, method: str, path: str, **kwargs: Any) -> Any:
        response = self._send(method, path, **kwargs)
        if response.status_code >= 400:
            raise _ApiError.from_response(response, f"{method} {path}")
        if response.status_code == 204 or not response.content:
            return None
        try:
            return response.json()
        except ValueError as e:
            raise _UnexpectedResponseError(
                f"{method} {path}", f"HTTP {response.status_code} body is not JSON"
            ) from e

    def _send(self, method: str, path: str, **kwargs: Any) -> requests.Response:
        # Why not retry only idempotent methods: a retried POST whose first attempt did create
        # the record gets 409, which add_txt_record resolves to the existing record.
        url = self.endpoint + path
        attempt = 1
        while True:
            try:
                response = self.session.request(method, url, timeout=self.timeout, **kwargs)
            except (requests.ConnectionError, requests.Timeout) as e:
                if attempt >= self.max_attempts:
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
                retry_wait = self._retry_wait(response, attempt)
                if retry_wait is None:
                    return response
                wait = retry_wait
                logger.info(
                    "Muumuu Domain API returned HTTP %d; retrying in %d seconds",
                    response.status_code,
                    wait,
                )
            self._sleep(wait)
            attempt += 1

    def _retry_wait(self, response: requests.Response, attempt: int) -> int | None:
        if response.status_code not in self.retryable_statuses or attempt >= self.max_attempts:
            return None
        if response.status_code in (429, 503) and "Retry-After" in response.headers:
            wait = _retry_after(response.headers["Retry-After"])
        elif response.status_code == 429:
            wait = DEFAULT_RETRY_AFTER
        else:
            wait = self._backoff(attempt)
        return wait if wait <= self.max_retry_after else None

    @staticmethod
    def _backoff(attempt: int) -> int:
        # Why not return 2 ** n as is: int ** int is typed as Any (negative powers are floats).
        return int(2 ** (attempt - 1))


class _UnexpectedResponseError(errors.PluginError):
    def __init__(self, request: str, problem: str) -> None:
        super().__init__(f"Unexpected response from the Muumuu Domain API ({request}): {problem}")


class _ApiError(errors.PluginError):
    def __init__(self, status_code: int, code: str, message: str, request: str = "") -> None:
        self.status_code = status_code
        self.code = code
        super().__init__(self._describe(status_code, code, message, request))

    @classmethod
    def from_response(cls, response: requests.Response, request: str = "") -> "_ApiError":
        try:
            body = response.json()
        except ValueError:
            body = None
        error = body.get("error") if isinstance(body, dict) else None
        if not isinstance(error, dict):
            error = {}
        code = error.get("code")
        message = error.get("message")
        return cls(
            response.status_code,
            code if isinstance(code, str) else "",
            message if isinstance(message, str) and message else response.reason or "",
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


def _dict(value: Any, context: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise _UnexpectedResponseError(context, f"expected an object, got {value!r}")
    return value


def _data(body: Any, context: str) -> Any:
    return _dict(body, context).get("data")


def _str(item: dict[str, Any], key: str, context: str) -> str:
    value = item.get(key)
    if not isinstance(value, str):
        raise _UnexpectedResponseError(context, f"{key!r} is not a string in {item!r}")
    return value


def _parse_domain(item: Any) -> _Domain:
    item = _dict(item, "domain")
    return _Domain(id=_str(item, "id", "domain"), fqdn=_str(item, "fqdn", "domain"))


def _parse_nameserver_settings(item: Any) -> _NameserverSettings:
    item = _dict(item, "nameserver settings")
    nameservers = item.get("nameservers") or []
    if not isinstance(nameservers, list) or not all(isinstance(n, str) for n in nameservers):
        raise _UnexpectedResponseError(
            "nameserver settings", f"'nameservers' is not a list of strings in {item!r}"
        )
    return _NameserverSettings(
        setup_type=_str(item, "setup-type", "nameserver settings"),
        nameservers=tuple(nameservers),
    )


def _parse_txt_record(item: Any) -> _TxtRecord:
    item = _dict(item, "DNS record")
    record_id = item.get("id")
    # Why not isinstance(record_id, int) alone: bool is a subclass of int.
    if not isinstance(record_id, int) or isinstance(record_id, bool):
        raise _UnexpectedResponseError("DNS record", f"'id' is not an integer in {item!r}")
    return _TxtRecord(
        id=record_id,
        fqdn=_str(item, "fqdn", "DNS record"),
        value=_str(item, "value", "DNS record"),
    )


def _is_valid_endpoint(endpoint: str) -> bool:
    try:
        url = urlsplit(endpoint)
    except ValueError:
        return False
    return url.scheme == "https" and bool(url.hostname) and not url.query and not url.fragment


def _hostname(endpoint: str) -> str | None:
    return urlsplit(endpoint).hostname


def _normalize(fqdn: str) -> str:
    return fqdn.rstrip(".").lower()


def _unquote(value: str) -> str:
    # Why not compare as-is: the API returns TXT values unquoted today, but the zone file
    # representation is quoted and either form must match the validation token.
    if len(value) >= 2 and value[0] == value[-1] == '"':
        return value[1:-1]
    return value


def _retry_after(header: str) -> int:
    try:
        return max(int(header), 1)
    except ValueError:
        pass
    try:
        when = parsedate_to_datetime(header)
    except (TypeError, ValueError):
        return DEFAULT_RETRY_AFTER
    if when.tzinfo is None:
        when = when.replace(tzinfo=timezone.utc)
    return max(int((when - datetime.now(timezone.utc)).total_seconds()), 1)
