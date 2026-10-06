"""Tests for certbot_dns_muumuu._internal.dns_muumuu."""

import logging
import sys
from collections.abc import Iterator
from datetime import datetime, timedelta, timezone
from email.utils import format_datetime
from typing import Any
from unittest import mock

import pytest
import requests
import responses
from acme import messages
from certbot import achallenges, errors
from certbot.compat import os
from certbot.plugins import dns_test_common
from certbot.plugins.dns_test_common import DOMAIN
from certbot.tests import acme_util
from certbot.tests import util as test_util
from responses import matchers

from certbot_dns_muumuu._internal.dns_muumuu import (
    DEFAULT_ENDPOINT,
    Authenticator,
    _Domain,
    _MuumuuClient,
    _NameserverSettings,
)

TOKEN = "muu_pat_0123456789abcdef"
SANDBOX_TOKEN = "muu_pat_sandbox_0123456789abcdef"
SANDBOX = "https://api-sandbox.muumuu-domain.com/api/v2"
DOMAIN_ID = "MU00000001"
RECORD_NAME = "_acme-challenge.example.com"
RECORD_CONTENT = "bar"


def _achall(domain: str) -> achallenges.KeyAuthorizationAnnotatedChallenge:
    common: dict[str, Any] = {"challb": acme_util.DNS01, "account_key": dns_test_common.KEY}
    # Why not pass `identifier` only: Certbot 4 (the minimum supported) takes `domain`.
    try:
        return achallenges.KeyAuthorizationAnnotatedChallenge(
            identifier=messages.Identifier(typ=messages.IDENTIFIER_FQDN, value=domain), **common
        )
    except TypeError:  # pragma: no cover
        return achallenges.KeyAuthorizationAnnotatedChallenge(domain=domain, **common)


class AuthenticatorTest(test_util.TempDirTestCase, dns_test_common.BaseAuthenticatorTest):
    def setUp(self) -> None:
        super().setUp()

        path = os.path.join(self.tempdir, "file.ini")
        dns_test_common.write({"muumuu_token": TOKEN}, path)

        self.config = mock.MagicMock(muumuu_credentials=path, muumuu_propagation_seconds=0)
        self.auth = Authenticator(self.config, "muumuu")

        self.mock_client = mock.MagicMock()
        self.mock_client.find_domain.return_value = _Domain(DOMAIN_ID, DOMAIN)
        self.mock_client.get_nameserver_settings.return_value = _NameserverSettings(
            "muumuu_dns", ("dns01.muumuu-domain.com", "dns02.muumuu-domain.com")
        )
        self.mock_client.add_txt_record.return_value = 42
        self.auth._get_client = mock.MagicMock(return_value=self.mock_client)  # type: ignore[method-assign]

    def _prepare_cleanup(self) -> None:
        self.auth._setup_credentials()
        self.auth._attempt_cleanup = True
        self.auth._domain_ids[DOMAIN] = DOMAIN_ID

    @test_util.patch_display_util()
    def test_perform(self, unused_mock_get_utility: Any) -> None:
        self.auth.perform([self.achall])

        self.mock_client.find_domain.assert_called_once_with(DOMAIN)
        self.mock_client.add_txt_record.assert_called_once_with(
            DOMAIN_ID, "_acme-challenge." + DOMAIN, mock.ANY
        )

    @test_util.patch_display_util()
    def test_perform_looks_up_each_zone_once(self, unused_mock_get_utility: Any) -> None:
        self.auth.perform(
            [self.achall, _achall("a." + DOMAIN), _achall("b.c." + DOMAIN), _achall(DOMAIN)]
        )

        self.mock_client.find_domain.assert_called_once_with(DOMAIN)
        self.mock_client.get_nameserver_settings.assert_called_once_with(DOMAIN_ID)
        assert self.mock_client.add_txt_record.call_count == 4

    @test_util.patch_display_util()
    def test_perform_looks_up_other_zones(self, unused_mock_get_utility: Any) -> None:
        self.mock_client.find_domain.side_effect = [
            _Domain(DOMAIN_ID, DOMAIN),
            _Domain("MU00000002", "example.org"),
        ]

        self.auth.perform([self.achall, _achall("www.example.org")])

        assert self.mock_client.add_txt_record.call_args_list == [
            mock.call(DOMAIN_ID, "_acme-challenge." + DOMAIN, mock.ANY),
            mock.call("MU00000002", "_acme-challenge.www.example.org", mock.ANY),
        ]

    @test_util.patch_display_util()
    def test_perform_warns_once_per_zone_unless_muumuu_dns(
        self, unused_mock_get_utility: Any
    ) -> None:
        self.mock_client.get_nameserver_settings.return_value = _NameserverSettings(
            "custom", ("ns1.example.net", "ns2.example.net")
        )

        with self.assertLogs("certbot_dns_muumuu", logging.WARNING) as logs:
            self.auth.perform([self.achall, _achall("www." + DOMAIN)])

        assert len(logs.output) == 1
        assert "setup-type: custom" in logs.output[0]
        assert "ns1.example.net, ns2.example.net" in logs.output[0]
        assert self.mock_client.add_txt_record.call_count == 2

    @test_util.patch_display_util()
    def test_perform_warning_without_nameservers(self, unused_mock_get_utility: Any) -> None:
        self.mock_client.get_nameserver_settings.return_value = _NameserverSettings("parking", ())

        with self.assertLogs("certbot_dns_muumuu", logging.WARNING) as logs:
            self.auth.perform([self.achall])

        assert "nameservers: none" in logs.output[0]

    @test_util.patch_display_util()
    def test_perform_continues_when_nameserver_check_fails(
        self, unused_mock_get_utility: Any
    ) -> None:
        self.mock_client.get_nameserver_settings.side_effect = errors.PluginError("HTTP 503")

        with self.assertNoLogs("certbot_dns_muumuu", logging.WARNING):
            self.auth.perform([self.achall])

        self.mock_client.add_txt_record.assert_called_once()

    @test_util.patch_display_util()
    def test_perform_propagates_errors(self, unused_mock_get_utility: Any) -> None:
        self.mock_client.find_domain.side_effect = errors.PluginError("not found")

        with pytest.raises(errors.PluginError):
            self.auth.perform([self.achall])

    @test_util.patch_display_util()
    def test_cleanup_deletes_created_record(self, unused_mock_get_utility: Any) -> None:
        self.auth.perform([self.achall])
        self.auth.cleanup([self.achall])

        self.mock_client.delete_record.assert_called_once_with(DOMAIN_ID, 42)
        self.mock_client.find_txt_record_ids.assert_not_called()

    def test_cleanup_without_known_record_matches_by_value(self) -> None:
        self._prepare_cleanup()
        self.mock_client.find_txt_record_ids.return_value = [7]

        self.auth.cleanup([self.achall])

        self.mock_client.find_txt_record_ids.assert_called_once_with(
            DOMAIN_ID, "_acme-challenge." + DOMAIN, mock.ANY
        )
        self.mock_client.delete_record.assert_called_once_with(DOMAIN_ID, 7)

    def test_cleanup_without_matching_record(self) -> None:
        self._prepare_cleanup()
        self.mock_client.find_txt_record_ids.return_value = []

        self.auth.cleanup([self.achall])

        self.mock_client.delete_record.assert_not_called()

    def test_cleanup_continues_after_a_failed_deletion(self) -> None:
        self._prepare_cleanup()
        self.mock_client.find_txt_record_ids.return_value = [7, 8]
        self.mock_client.delete_record.side_effect = [errors.PluginError("HTTP 500"), None]

        with self.assertLogs("certbot_dns_muumuu", logging.WARNING) as logs:
            self.auth.cleanup([self.achall])

        assert self.mock_client.delete_record.call_args_list == [
            mock.call(DOMAIN_ID, 7),
            mock.call(DOMAIN_ID, 8),
        ]
        assert "(id 7)" in logs.output[0]
        assert "HTTP 500" in logs.output[0]

    def test_cleanup_logs_lookup_errors(self) -> None:
        self._prepare_cleanup()
        self.mock_client.find_txt_record_ids.side_effect = errors.PluginError("HTTP 502")

        with self.assertLogs("certbot_dns_muumuu", logging.WARNING) as logs:
            self.auth.cleanup([self.achall])

        assert "HTTP 502" in logs.output[0]
        self.mock_client.delete_record.assert_not_called()

    @test_util.patch_display_util()
    def test_cleanup_after_failed_domain_lookup_does_nothing(
        self, unused_mock_get_utility: Any
    ) -> None:
        self.mock_client.find_domain.side_effect = errors.PluginError("not found")
        with pytest.raises(errors.PluginError):
            self.auth.perform([self.achall])

        with self.assertNoLogs("certbot_dns_muumuu", logging.WARNING):
            self.auth.cleanup([self.achall])

        self.mock_client.find_domain.assert_called_once()
        self.mock_client.get_nameserver_settings.assert_not_called()
        self.mock_client.find_txt_record_ids.assert_not_called()
        self.mock_client.delete_record.assert_not_called()

    @test_util.patch_display_util()
    def test_cleanup_after_failed_creation_matches_by_value(
        self, unused_mock_get_utility: Any
    ) -> None:
        self.mock_client.add_txt_record.side_effect = errors.PluginError("network error")
        self.mock_client.find_txt_record_ids.return_value = [9]
        with pytest.raises(errors.PluginError):
            self.auth.perform([self.achall])

        self.auth.cleanup([self.achall])

        self.mock_client.delete_record.assert_called_once_with(DOMAIN_ID, 9)

    def test_cleanup_closes_the_client(self) -> None:
        self._prepare_cleanup()
        self.mock_client.find_txt_record_ids.return_value = []
        self.auth._client = self.mock_client

        self.auth.cleanup([self.achall])

        self.mock_client.close.assert_called_once_with()
        assert self.auth._client is None

    def test_cleanup_closes_the_client_on_unexpected_errors(self) -> None:
        self._prepare_cleanup()
        self.mock_client.find_txt_record_ids.side_effect = RuntimeError("bug")
        self.auth._client = self.mock_client

        with pytest.raises(RuntimeError):
            self.auth.cleanup([self.achall])

        self.mock_client.close.assert_called_once_with()

    def test_missing_token(self) -> None:
        dns_test_common.write({}, self.config.muumuu_credentials)

        with pytest.raises(errors.PluginError):
            self.auth._setup_credentials()


class CredentialsTest(test_util.TempDirTestCase):
    def _auth(self, values: dict[str, str]) -> Authenticator:
        path = os.path.join(self.tempdir, "file.ini")
        dns_test_common.write(values, path)
        config = mock.MagicMock(muumuu_credentials=path, muumuu_propagation_seconds=0)
        auth = Authenticator(config, "muumuu")
        auth._setup_credentials()
        return auth

    def test_default_endpoint(self) -> None:
        client = self._auth({"muumuu_token": TOKEN})._get_client()

        assert client.endpoint == DEFAULT_ENDPOINT
        assert client.session.headers["Authorization"] == f"Bearer {TOKEN}"
        client.close()

    def test_custom_endpoint(self) -> None:
        client = self._auth({"muumuu_token": TOKEN, "muumuu_endpoint": SANDBOX + "/"})._get_client()

        assert client.endpoint == SANDBOX
        client.close()

    def test_sandbox_token_with_sandbox_endpoint(self) -> None:
        auth = self._auth({"muumuu_token": SANDBOX_TOKEN, "muumuu_endpoint": SANDBOX})

        assert auth.credentials is not None

    def test_rejects_token_without_prefix(self) -> None:
        with pytest.raises(errors.PluginError, match="should start with muu_pat_"):
            self._auth({"muumuu_token": "0123456789abcdef"})

    def test_rejects_sandbox_token_for_production(self) -> None:
        for values in (
            {"muumuu_token": SANDBOX_TOKEN},
            {"muumuu_token": SANDBOX_TOKEN, "muumuu_endpoint": DEFAULT_ENDPOINT + "/"},
        ):
            with pytest.raises(errors.PluginError, match="sandbox token"):
                self._auth(values)

    def test_rejects_invalid_endpoints(self) -> None:
        for endpoint in (
            "http://muumuu-domain.com/api/v2",
            "muumuu-domain.com/api/v2",
            "https:///api/v2",
            "https://muumuu-domain.com/api/v2?debug=1",
            "https://muumuu-domain.com/api/v2#top",
            "https://[::1/api/v2",
        ):
            with pytest.raises(errors.PluginError, match="must be an https:// URL"):
                self._auth({"muumuu_token": TOKEN, "muumuu_endpoint": endpoint})


def _page(items: list[Any], total: int | None = None, page: int = 1) -> dict[str, Any]:
    meta = {"page": page, "page-size": 100}
    if total is not None:
        meta["total"] = total
    return {"data": items, "meta": meta}


def _txt(record_id: int, value: str, fqdn: str = RECORD_NAME + ".") -> dict[str, Any]:
    return {"id": record_id, "fqdn": fqdn, "type": "TXT", "value": value, "ttl": 3600}


def _url(path: str) -> str:
    return SANDBOX + path


DOMAINS_URL = _url("/me/domains")
NAMESERVERS_URL = _url(f"/me/domains/{DOMAIN_ID}/nameservers")
RECORDS_URL = _url(f"/me/domains/{DOMAIN_ID}/dns-records")


@pytest.fixture
def sleep() -> mock.MagicMock:
    return mock.MagicMock()


@pytest.fixture
def client(sleep: mock.MagicMock) -> Iterator[_MuumuuClient]:
    client = _MuumuuClient(TOKEN, SANDBOX, sleep=sleep)
    yield client
    client.close()


@pytest.fixture
def rsps() -> Iterator[responses.RequestsMock]:
    with responses.RequestsMock(assert_all_requests_are_fired=True) as rsps:
        yield rsps


def _domains(rsps: responses.RequestsMock, fqdn: str, items: list[dict[str, Any]]) -> None:
    rsps.get(
        DOMAINS_URL,
        match=[matchers.query_param_matcher({"fqdn": fqdn}, strict_match=False)],
        json=_page(items, len(items)),
    )


class TestFindDomain:
    def test_sub_domain(self, client: _MuumuuClient, rsps: responses.RequestsMock) -> None:
        _domains(rsps, "www.sub.example.com", [])
        _domains(rsps, "sub.example.com", [])
        _domains(rsps, "example.com", [{"id": DOMAIN_ID, "fqdn": "example.com"}])

        assert client.find_domain("www.sub.example.com") == _Domain(DOMAIN_ID, "example.com")
        headers = rsps.calls[0].request.headers
        assert headers["Authorization"] == f"Bearer {TOKEN}"
        assert headers["User-Agent"].startswith("certbot-dns-muumuu")

    def test_multi_label_tld(self, client: _MuumuuClient, rsps: responses.RequestsMock) -> None:
        _domains(rsps, "www.example.co.jp", [])
        _domains(rsps, "example.co.jp", [{"id": "MU00000002", "fqdn": "example.co.jp"}])

        assert client.find_domain("www.example.co.jp") == _Domain("MU00000002", "example.co.jp")

    def test_ignores_inexact_matches(
        self, client: _MuumuuClient, rsps: responses.RequestsMock
    ) -> None:
        _domains(rsps, "example.com", [{"id": DOMAIN_ID, "fqdn": "other.com"}])

        with pytest.raises(errors.PluginError, match="Unable to find"):
            client.find_domain("example.com")

    def test_not_found_does_not_query_bare_tld(
        self, client: _MuumuuClient, rsps: responses.RequestsMock
    ) -> None:
        _domains(rsps, "www.example.com", [])
        _domains(rsps, "example.com", [])

        with pytest.raises(errors.PluginError, match=r"tried: www.example.com, example.com\)"):
            client.find_domain("www.example.com")
        assert len(rsps.calls) == 2

    def test_skips_guesses_rejected_by_the_api(
        self, client: _MuumuuClient, rsps: responses.RequestsMock
    ) -> None:
        _domains(rsps, "example.co.jp", [])
        rsps.get(
            DOMAINS_URL,
            match=[matchers.query_param_matcher({"fqdn": "co.jp"}, strict_match=False)],
            status=400,
            json={"error": {"code": "bad_request", "message": "Invalid fqdn parameter format"}},
        )

        with pytest.raises(errors.PluginError, match="Unable to find a Muumuu Domain domain"):
            client.find_domain("example.co.jp")

    def test_reads_further_pages(self, client: _MuumuuClient, rsps: responses.RequestsMock) -> None:
        client.page_size = 2
        others = [{"id": f"MU0000000{i}", "fqdn": f"other{i}.com"} for i in (2, 3)]
        rsps.get(
            DOMAINS_URL,
            match=[
                matchers.query_param_matcher(
                    {"fqdn": "example.com", "page": "1"}, strict_match=False
                )
            ],
            json=_page(others, 3),
        )
        rsps.get(
            DOMAINS_URL,
            match=[
                matchers.query_param_matcher(
                    {"fqdn": "example.com", "page": "2"}, strict_match=False
                )
            ],
            json=_page([{"id": DOMAIN_ID, "fqdn": "example.com"}], 3, page=2),
        )

        assert client.find_domain("example.com") == _Domain(DOMAIN_ID, "example.com")

    @pytest.mark.parametrize(
        ("status", "code", "hint"),
        [
            (401, "invalid_token", "Check dns_muumuu_token"),
            (403, "insufficient_scope", "domains:read, dns:read, dns:write"),
        ],
    )
    def test_authentication_errors(
        self,
        client: _MuumuuClient,
        rsps: responses.RequestsMock,
        status: int,
        code: str,
        hint: str,
    ) -> None:
        rsps.get(DOMAINS_URL, status=status, json={"error": {"code": code, "message": "nope"}})

        with pytest.raises(errors.PluginError, match=f"HTTP {status} {code}: nope.*{hint}"):
            client.find_domain("example.com")


class TestErrorResponses:
    @pytest.mark.parametrize(
        "kwargs",
        [
            {"body": "<html>Not Found</html>"},
            {"json": {"error": None}},
            {"json": {"error": "not_found"}},
            {"json": ["not_found"]},
            {"json": {"error": {"code": 404, "message": None}}},
        ],
    )
    def test_malformed_error_bodies_become_api_errors(
        self, client: _MuumuuClient, rsps: responses.RequestsMock, kwargs: dict[str, Any]
    ) -> None:
        rsps.get(NAMESERVERS_URL, status=404, **kwargs)

        with pytest.raises(
            errors.PluginError, match=rf"^HTTP 404: Not Found \(GET /me/domains/{DOMAIN_ID}"
        ):
            client.get_nameserver_settings(DOMAIN_ID)

    @pytest.mark.parametrize(
        "kwargs",
        [
            {"body": "<html>Maintenance</html>"},
            {"json": ["unexpected"]},
            {"json": {"data": None}},
            {"json": {"data": {"setup-type": 1, "nameservers": []}}},
            {"json": {"data": {"setup-type": "custom", "nameservers": "ns1.example.net"}}},
            {"json": {"data": {"setup-type": "custom", "nameservers": [{"name": "ns1"}]}}},
        ],
    )
    def test_malformed_nameserver_settings(
        self, client: _MuumuuClient, rsps: responses.RequestsMock, kwargs: dict[str, Any]
    ) -> None:
        rsps.get(NAMESERVERS_URL, **kwargs)

        with pytest.raises(errors.PluginError, match="Unexpected response"):
            client.get_nameserver_settings(DOMAIN_ID)

    @pytest.mark.parametrize(
        "kwargs",
        [
            {"body": ""},
            {"json": {"data": None}},
            {"json": {"data": {"id": "1", "fqdn": RECORD_NAME + ".", "value": "bar"}}},
            {"json": {"data": {"id": True, "fqdn": RECORD_NAME + ".", "value": "bar"}}},
            {"json": {"data": {"id": 1, "fqdn": RECORD_NAME + "."}}},
        ],
    )
    def test_malformed_created_record(
        self, client: _MuumuuClient, rsps: responses.RequestsMock, kwargs: dict[str, Any]
    ) -> None:
        rsps.post(RECORDS_URL, status=201, **kwargs)

        with pytest.raises(errors.PluginError, match="Unexpected response"):
            client.add_txt_record(DOMAIN_ID, RECORD_NAME, RECORD_CONTENT)

    @pytest.mark.parametrize(
        "body",
        [
            {"data": None},
            {"data": {"id": 1}},
            {"data": ["not a record"]},
            {"data": [{"id": 1, "fqdn": None, "value": "bar"}]},
            {"data": [{"id": None, "fqdn": "example.com", "value": "bar"}]},
        ],
    )
    def test_malformed_lists(
        self, client: _MuumuuClient, rsps: responses.RequestsMock, body: dict[str, Any]
    ) -> None:
        rsps.get(RECORDS_URL, json=body)
        rsps.get(DOMAINS_URL, json=body)

        with pytest.raises(errors.PluginError, match="Unexpected response"):
            client.find_txt_record_ids(DOMAIN_ID, RECORD_NAME, RECORD_CONTENT)
        with pytest.raises(errors.PluginError, match="Unexpected response"):
            client.find_domain("example.com")


class TestNameserverSettings:
    def test_settings(self, client: _MuumuuClient, rsps: responses.RequestsMock) -> None:
        rsps.get(
            NAMESERVERS_URL,
            json={
                "data": {
                    "domain-id": DOMAIN_ID,
                    "setup-type": "muumuu_dns",
                    "nameservers": ["dns01.muumuu-domain.com", "dns02.muumuu-domain.com"],
                }
            },
        )

        assert client.get_nameserver_settings(DOMAIN_ID) == _NameserverSettings(
            "muumuu_dns", ("dns01.muumuu-domain.com", "dns02.muumuu-domain.com")
        )

    def test_missing_nameservers(self, client: _MuumuuClient, rsps: responses.RequestsMock) -> None:
        rsps.get(NAMESERVERS_URL, json={"data": {"setup-type": "parking", "nameservers": None}})

        assert client.get_nameserver_settings(DOMAIN_ID) == _NameserverSettings("parking", ())


class TestTxtRecords:
    def test_add(self, client: _MuumuuClient, rsps: responses.RequestsMock) -> None:
        rsps.post(
            RECORDS_URL,
            status=201,
            match=[
                matchers.json_params_matcher(
                    {"fqdn": RECORD_NAME, "type": "TXT", "value": RECORD_CONTENT},
                    strict_match=True,
                )
            ],
            json={"data": _txt(42, RECORD_CONTENT)},
        )

        assert client.add_txt_record(DOMAIN_ID, RECORD_NAME, RECORD_CONTENT) == 42

    def test_add_conflict_reuses_existing_record(
        self, client: _MuumuuClient, rsps: responses.RequestsMock
    ) -> None:
        rsps.post(
            RECORDS_URL,
            status=409,
            json={
                "error": {
                    "code": "conflict",
                    "message": "A record with the same fqdn, type, and value already exists",
                }
            },
        )
        rsps.get(RECORDS_URL, json=_page([_txt(1, "other"), _txt(2, RECORD_CONTENT)], 2))

        assert client.add_txt_record(DOMAIN_ID, RECORD_NAME, RECORD_CONTENT) == 2

    def test_add_conflict_without_matching_record(
        self, client: _MuumuuClient, rsps: responses.RequestsMock
    ) -> None:
        rsps.post(
            RECORDS_URL,
            status=409,
            json={"error": {"code": "conflict", "message": "The resource already exists"}},
        )
        rsps.get(RECORDS_URL, json=_page([], 0))

        with pytest.raises(errors.PluginError, match="HTTP 409 conflict"):
            client.add_txt_record(DOMAIN_ID, RECORD_NAME, RECORD_CONTENT)

    def test_add_limit_exceeded(self, client: _MuumuuClient, rsps: responses.RequestsMock) -> None:
        rsps.post(
            RECORDS_URL,
            status=400,
            json={"error": {"code": "bad_request", "message": "Record limit exceeded"}},
        )

        with pytest.raises(errors.PluginError, match="Record limit exceeded"):
            client.add_txt_record(DOMAIN_ID, RECORD_NAME, RECORD_CONTENT)

    def test_retried_post_that_succeeded_reuses_the_record(
        self, client: _MuumuuClient, rsps: responses.RequestsMock
    ) -> None:
        rsps.post(RECORDS_URL, body=requests.ReadTimeout("read timed out"))
        rsps.post(
            RECORDS_URL, status=409, json={"error": {"code": "conflict", "message": "exists"}}
        )
        rsps.get(RECORDS_URL, json=_page([_txt(5, RECORD_CONTENT)], 1))

        assert client.add_txt_record(DOMAIN_ID, RECORD_NAME, RECORD_CONTENT) == 5

    def test_find_paginates_and_matches_by_value(
        self, client: _MuumuuClient, rsps: responses.RequestsMock
    ) -> None:
        base = {"type": "TXT", "fqdn": RECORD_NAME + ".", "page-size": "100"}
        first = [_txt(i, f"other-{i}") for i in range(1, 100)]
        first.append(_txt(100, f'"{RECORD_CONTENT}"'))
        rsps.get(
            RECORDS_URL,
            match=[matchers.query_param_matcher({**base, "page": "1"})],
            json=_page(first, 102),
        )
        rsps.get(
            RECORDS_URL,
            match=[matchers.query_param_matcher({**base, "page": "2"})],
            json=_page(
                [
                    _txt(101, RECORD_CONTENT, fqdn="sub." + RECORD_NAME + "."),
                    _txt(102, RECORD_CONTENT, fqdn=RECORD_NAME.upper() + "."),
                ],
                102,
                page=2,
            ),
        )

        assert client.find_txt_record_ids(DOMAIN_ID, RECORD_NAME, RECORD_CONTENT) == [100, 102]

    def test_find_stops_on_a_short_page_without_meta(
        self, client: _MuumuuClient, rsps: responses.RequestsMock
    ) -> None:
        rsps.get(RECORDS_URL, json={"data": [_txt(1, RECORD_CONTENT)], "meta": "unexpected"})

        assert client.find_txt_record_ids(DOMAIN_ID, RECORD_NAME, RECORD_CONTENT) == [1]

    def test_find_stops_at_total(self, client: _MuumuuClient, rsps: responses.RequestsMock) -> None:
        client.page_size = 1
        rsps.get(RECORDS_URL, json=_page([_txt(1, RECORD_CONTENT)], 1))

        assert client.find_txt_record_ids(DOMAIN_ID, RECORD_NAME, RECORD_CONTENT) == [1]

    def test_find_gives_up_after_max_pages(
        self,
        client: _MuumuuClient,
        rsps: responses.RequestsMock,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        client.page_size = 1
        client.max_pages = 2
        rsps.get(RECORDS_URL, json={"data": [_txt(1, "other")]})

        assert client.find_txt_record_ids(DOMAIN_ID, RECORD_NAME, RECORD_CONTENT) == []
        assert len(rsps.calls) == 2
        assert "after 2 pages" in caplog.text

    def test_delete(self, client: _MuumuuClient, rsps: responses.RequestsMock) -> None:
        rsps.delete(RECORDS_URL + "/42", status=204)

        client.delete_record(DOMAIN_ID, 42)

    def test_delete_already_gone(self, client: _MuumuuClient, rsps: responses.RequestsMock) -> None:
        rsps.delete(
            RECORDS_URL + "/42",
            status=404,
            json={"error": {"code": "not_found", "message": "Not found"}},
        )

        client.delete_record(DOMAIN_ID, 42)

    def test_delete_error(self, client: _MuumuuClient, rsps: responses.RequestsMock) -> None:
        rsps.delete(
            RECORDS_URL + "/42",
            status=500,
            json={"error": {"code": "internal_error", "message": "Internal error"}},
        )

        with pytest.raises(errors.PluginError, match="HTTP 500"):
            client.delete_record(DOMAIN_ID, 42)


class TestRetries:
    def _ok(self, rsps: responses.RequestsMock) -> None:
        rsps.get(NAMESERVERS_URL, json={"data": {"setup-type": "muumuu_dns"}})

    def test_rate_limit_honours_retry_after(
        self, client: _MuumuuClient, rsps: responses.RequestsMock, sleep: mock.MagicMock
    ) -> None:
        rsps.get(NAMESERVERS_URL, status=429, headers={"Retry-After": "7"}, json={})
        rsps.get(NAMESERVERS_URL, status=429, headers={"Retry-After": "bogus"}, json={})
        self._ok(rsps)

        assert client.get_nameserver_settings(DOMAIN_ID).setup_type == "muumuu_dns"
        assert sleep.call_args_list == [mock.call(7), mock.call(60)]

    def test_rate_limit_without_retry_after(
        self, client: _MuumuuClient, rsps: responses.RequestsMock, sleep: mock.MagicMock
    ) -> None:
        rsps.get(NAMESERVERS_URL, status=429, json={})
        self._ok(rsps)

        client.get_nameserver_settings(DOMAIN_ID)

        assert sleep.call_args_list == [mock.call(60)]

    def test_retry_after_http_date(
        self, client: _MuumuuClient, rsps: responses.RequestsMock, sleep: mock.MagicMock
    ) -> None:
        when = datetime.now(timezone.utc) + timedelta(seconds=120)
        rsps.get(NAMESERVERS_URL, status=429, headers={"Retry-After": format_datetime(when, True)})
        self._ok(rsps)

        client.get_nameserver_settings(DOMAIN_ID)

        (wait,) = (c.args[0] for c in sleep.call_args_list)
        assert 100 <= wait <= 120

    def test_retry_after_http_date_in_the_past(
        self, client: _MuumuuClient, rsps: responses.RequestsMock, sleep: mock.MagicMock
    ) -> None:
        rsps.get(
            NAMESERVERS_URL,
            status=429,
            headers={"Retry-After": "Wed, 21 Oct 2015 07:28:00 -0000"},
        )
        self._ok(rsps)

        client.get_nameserver_settings(DOMAIN_ID)

        assert sleep.call_args_list == [mock.call(1)]

    def test_service_unavailable_honours_retry_after(
        self, client: _MuumuuClient, rsps: responses.RequestsMock, sleep: mock.MagicMock
    ) -> None:
        rsps.get(NAMESERVERS_URL, status=503, headers={"Retry-After": "120"}, json={})
        self._ok(rsps)

        client.get_nameserver_settings(DOMAIN_ID)

        assert sleep.call_args_list == [mock.call(120)]

    def test_server_errors_back_off(
        self, client: _MuumuuClient, rsps: responses.RequestsMock, sleep: mock.MagicMock
    ) -> None:
        rsps.get(NAMESERVERS_URL, status=503, json={"error": {"code": "service_unavailable"}})
        rsps.get(NAMESERVERS_URL, status=502, body="Bad Gateway")
        self._ok(rsps)

        client.get_nameserver_settings(DOMAIN_ID)

        assert sleep.call_args_list == [mock.call(1), mock.call(2)]

    def test_gives_up_after_max_attempts(
        self, client: _MuumuuClient, rsps: responses.RequestsMock, sleep: mock.MagicMock
    ) -> None:
        for _ in range(3):
            rsps.get(
                NAMESERVERS_URL,
                status=429,
                headers={"Retry-After": "1"},
                json={"error": {"code": "rate_limit_exceeded", "message": "Rate limit exceeded"}},
            )

        with pytest.raises(errors.PluginError, match="HTTP 429 rate_limit_exceeded.*try again"):
            client.get_nameserver_settings(DOMAIN_ID)
        assert sleep.call_count == 2

    @pytest.mark.parametrize("status", [429, 503])
    def test_does_not_wait_for_long_retry_after(
        self,
        client: _MuumuuClient,
        rsps: responses.RequestsMock,
        sleep: mock.MagicMock,
        status: int,
    ) -> None:
        rsps.get(NAMESERVERS_URL, status=status, headers={"Retry-After": "3600"}, json={})

        with pytest.raises(errors.PluginError, match=f"HTTP {status}"):
            client.get_nameserver_settings(DOMAIN_ID)
        sleep.assert_not_called()

    def test_does_not_retry_client_errors(
        self, client: _MuumuuClient, rsps: responses.RequestsMock, sleep: mock.MagicMock
    ) -> None:
        rsps.get(
            NAMESERVERS_URL,
            status=404,
            json={"error": {"code": "not_found", "message": "Not found"}},
        )

        with pytest.raises(errors.PluginError, match="HTTP 404 not_found"):
            client.get_nameserver_settings(DOMAIN_ID)
        sleep.assert_not_called()

    def test_retries_network_errors(
        self, client: _MuumuuClient, rsps: responses.RequestsMock, sleep: mock.MagicMock
    ) -> None:
        rsps.get(NAMESERVERS_URL, body=requests.ConnectionError("connection reset"))
        rsps.get(NAMESERVERS_URL, body=requests.Timeout("read timed out"))
        self._ok(rsps)

        client.get_nameserver_settings(DOMAIN_ID)

        assert sleep.call_args_list == [mock.call(1), mock.call(2)]

    def test_persistent_network_error(
        self, client: _MuumuuClient, rsps: responses.RequestsMock
    ) -> None:
        for _ in range(3):
            rsps.get(NAMESERVERS_URL, body=requests.ConnectionError("connection refused"))

        with pytest.raises(errors.PluginError, match="Network error.*connection refused"):
            client.get_nameserver_settings(DOMAIN_ID)

    def test_other_request_errors_are_not_retried(
        self, client: _MuumuuClient, rsps: responses.RequestsMock, sleep: mock.MagicMock
    ) -> None:
        rsps.get(NAMESERVERS_URL, body=requests.TooManyRedirects("too many redirects"))

        with pytest.raises(errors.PluginError, match="too many redirects"):
            client.get_nameserver_settings(DOMAIN_ID)
        sleep.assert_not_called()


def test_close_closes_the_session() -> None:
    session = mock.MagicMock(spec=requests.Session, headers={})
    client = _MuumuuClient(TOKEN, session=session)

    client.close()

    session.close.assert_called_once_with()


if __name__ == "__main__":
    sys.exit(pytest.main(sys.argv[1:] + [__file__]))  # pragma: no cover
