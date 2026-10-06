"""Tests for certbot_dns_muumuu._internal.dns_muumuu."""

import logging
import sys
import unittest
from datetime import datetime, timedelta, timezone
from email.utils import format_datetime
from typing import Any
from unittest import mock

import pytest
import requests
import responses
from certbot import errors
from certbot.compat import os
from certbot.plugins import dns_test_common
from certbot.plugins.dns_test_common import DOMAIN
from certbot.tests import util as test_util
from responses import matchers

from certbot_dns_muumuu._internal.dns_muumuu import (
    DEFAULT_ENDPOINT,
    Authenticator,
    _MuumuuClient,
)

TOKEN = "muu_pat_0123456789abcdef"
SANDBOX = "https://api-sandbox.muumuu-domain.com/api/v2"
SANDBOX_TOKEN = "muu_pat_sandbox_0123456789abcdef"


class AuthenticatorTest(test_util.TempDirTestCase, dns_test_common.BaseAuthenticatorTest):
    def setUp(self) -> None:
        super().setUp()

        path = os.path.join(self.tempdir, "file.ini")
        dns_test_common.write({"muumuu_token": TOKEN}, path)

        self.config = mock.MagicMock(muumuu_credentials=path, muumuu_propagation_seconds=0)
        self.auth = Authenticator(self.config, "muumuu")

        self.mock_client = mock.MagicMock()
        self.mock_client.find_domain.return_value = ("MU00000001", DOMAIN)
        self.mock_client.get_nameserver_settings.return_value = {"setup-type": "muumuu_dns"}
        self.mock_client.add_txt_record.return_value = 42
        self.auth._get_client = mock.MagicMock(return_value=self.mock_client)  # type: ignore[method-assign]

    @test_util.patch_display_util()
    def test_perform(self, unused_mock_get_utility: Any) -> None:
        self.auth.perform([self.achall])

        self.mock_client.find_domain.assert_called_once_with(DOMAIN)
        self.mock_client.add_txt_record.assert_called_once_with(
            "MU00000001", "_acme-challenge." + DOMAIN, mock.ANY
        )

    @test_util.patch_display_util()
    def test_perform_looks_up_domain_once(self, unused_mock_get_utility: Any) -> None:
        self.auth.perform([self.achall, self.achall])

        self.mock_client.find_domain.assert_called_once_with(DOMAIN)
        self.mock_client.get_nameserver_settings.assert_called_once_with("MU00000001")
        assert self.mock_client.add_txt_record.call_count == 2

    @test_util.patch_display_util()
    def test_perform_warns_unless_muumuu_dns(self, unused_mock_get_utility: Any) -> None:
        self.mock_client.get_nameserver_settings.return_value = {
            "setup-type": "custom",
            "nameservers": ["ns1.example.net", "ns2.example.net"],
        }

        with self.assertLogs("certbot_dns_muumuu", logging.WARNING) as logs:
            self.auth.perform([self.achall])

        assert "setup-type: custom" in logs.output[0]
        assert "ns1.example.net, ns2.example.net" in logs.output[0]
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

        self.mock_client.delete_record.assert_called_once_with("MU00000001", 42)
        self.mock_client.find_txt_record_ids.assert_not_called()

    def test_cleanup_without_known_record_matches_by_value(self) -> None:
        self.auth._setup_credentials()
        self.auth._attempt_cleanup = True
        self.auth._domain_ids[DOMAIN] = "MU00000001"
        self.mock_client.find_txt_record_ids.return_value = [7]

        self.auth.cleanup([self.achall])

        self.mock_client.find_txt_record_ids.assert_called_once_with(
            "MU00000001", "_acme-challenge." + DOMAIN, mock.ANY
        )
        self.mock_client.delete_record.assert_called_once_with("MU00000001", 7)

    def test_cleanup_without_matching_record(self) -> None:
        self.auth._setup_credentials()
        self.auth._attempt_cleanup = True
        self.auth._domain_ids[DOMAIN] = "MU00000001"
        self.mock_client.find_txt_record_ids.return_value = []

        self.auth.cleanup([self.achall])

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

        self.mock_client.delete_record.assert_called_once_with("MU00000001", 9)

    @test_util.patch_display_util()
    def test_cleanup_logs_errors(self, unused_mock_get_utility: Any) -> None:
        self.auth.perform([self.achall])
        self.mock_client.delete_record.side_effect = errors.PluginError("boom")

        with self.assertLogs("certbot_dns_muumuu", logging.WARNING) as logs:
            self.auth.cleanup([self.achall])

        assert "boom" in logs.output[0]

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

    def test_custom_endpoint(self) -> None:
        auth = self._auth({"muumuu_token": TOKEN, "muumuu_endpoint": SANDBOX + "/"})

        assert auth._get_client().endpoint == SANDBOX

    def test_sandbox_token_with_sandbox_endpoint(self) -> None:
        auth = self._auth({"muumuu_token": SANDBOX_TOKEN, "muumuu_endpoint": SANDBOX})

        assert auth._get_client().endpoint == SANDBOX

    def test_rejects_token_without_prefix(self) -> None:
        with pytest.raises(errors.PluginError, match="should start with muu_pat_"):
            self._auth({"muumuu_token": "0123456789abcdef"})

    def test_rejects_sandbox_token_for_production(self) -> None:
        with pytest.raises(errors.PluginError, match="sandbox token"):
            self._auth({"muumuu_token": SANDBOX_TOKEN})

    def test_rejects_plain_http_endpoint(self) -> None:
        with pytest.raises(errors.PluginError, match="must be an https:// URL"):
            self._auth(
                {"muumuu_token": TOKEN, "muumuu_endpoint": "http://muumuu-domain.com/api/v2"}
            )

    def test_rejects_endpoint_without_host(self) -> None:
        with pytest.raises(errors.PluginError, match="must be an https:// URL"):
            self._auth({"muumuu_token": TOKEN, "muumuu_endpoint": "muumuu-domain.com/api/v2"})


def _records_page(records: list[dict[str, Any]], total: int, page: int = 1) -> dict[str, Any]:
    return {"data": records, "meta": {"total": total, "page": page, "page-size": 100}}


def _txt(record_id: int, fqdn: str, value: str) -> dict[str, Any]:
    return {"id": record_id, "fqdn": fqdn, "type": "TXT", "value": value, "ttl": 3600}


class MuumuuClientTest(unittest.TestCase):
    domain_id = "MU00000001"
    record_name = "_acme-challenge.example.com"
    record_content = "bar"

    def setUp(self) -> None:
        self.sleep = mock.MagicMock()
        self.client = _MuumuuClient(TOKEN, SANDBOX, sleep=self.sleep)
        self.rsps = responses.RequestsMock(assert_all_requests_are_fired=True)
        self.rsps.start()
        self.addCleanup(self.rsps.stop)
        self.addCleanup(self.rsps.reset)

    def _url(self, path: str) -> str:
        return SANDBOX + path

    def _domains(self, fqdn: str, data: list[dict[str, Any]]) -> None:
        self.rsps.get(
            self._url("/me/domains"),
            match=[matchers.query_param_matcher({"fqdn": fqdn})],
            json={"data": data, "meta": {"total": len(data), "page": 1, "page-size": 20}},
        )

    def test_find_domain_for_sub_domain(self) -> None:
        self._domains("www.sub.example.com", [])
        self._domains("sub.example.com", [])
        self._domains("example.com", [{"id": "MU00000001", "fqdn": "example.com"}])

        assert self.client.find_domain("www.sub.example.com") == ("MU00000001", "example.com")
        assert self.rsps.calls[0].request.headers["Authorization"] == f"Bearer {TOKEN}"
        assert self.rsps.calls[0].request.headers["User-Agent"].startswith("certbot-dns-muumuu")

    def test_find_domain_for_multi_label_tld(self) -> None:
        self._domains("www.example.co.jp", [])
        self._domains("example.co.jp", [{"id": "MU00000002", "fqdn": "example.co.jp"}])

        assert self.client.find_domain("www.example.co.jp") == ("MU00000002", "example.co.jp")

    def test_find_domain_ignores_inexact_matches(self) -> None:
        self._domains("example.com", [{"id": "MU00000001", "fqdn": "other.com"}])

        with pytest.raises(errors.PluginError, match="Unable to find"):
            self.client.find_domain("example.com")

    def test_find_domain_not_found_does_not_query_bare_tld(self) -> None:
        self._domains("www.example.com", [])
        self._domains("example.com", [])

        with pytest.raises(errors.PluginError, match=r"tried: www.example.com, example.com\)"):
            self.client.find_domain("www.example.com")
        assert len(self.rsps.calls) == 2

    def test_find_domain_skips_guesses_rejected_by_the_api(self) -> None:
        self._domains("example.co.jp", [])
        self.rsps.get(
            self._url("/me/domains"),
            match=[matchers.query_param_matcher({"fqdn": "co.jp"})],
            status=400,
            json={"error": {"code": "bad_request", "message": "Invalid fqdn parameter format"}},
        )

        with pytest.raises(errors.PluginError, match="Unable to find a Muumuu Domain domain"):
            self.client.find_domain("example.co.jp")

    def test_unauthorized(self) -> None:
        self.rsps.get(
            self._url("/me/domains"),
            status=401,
            json={"error": {"code": "invalid_token", "message": "The access token is invalid"}},
        )

        with pytest.raises(errors.PluginError, match="HTTP 401 invalid_token.*dns_muumuu_token"):
            self.client.find_domain("example.com")

    def test_insufficient_scope(self) -> None:
        self.rsps.get(
            self._url("/me/domains"),
            status=403,
            json={"error": {"code": "insufficient_scope", "message": "Insufficient scope"}},
        )

        with pytest.raises(errors.PluginError, match="domains:read, dns:read, dns:write"):
            self.client.find_domain("example.com")

    def test_non_json_error(self) -> None:
        self.rsps.get(self._url("/me/domains"), status=404, body="<html>Not Found</html>")

        with pytest.raises(errors.PluginError, match=r"HTTP 404: Not Found \(GET /me/domains\)"):
            self.client.find_domain("example.com")

    def test_non_json_success(self) -> None:
        self.rsps.get(self._url("/me/domains"), status=200, body="<html>Maintenance</html>")

        with pytest.raises(errors.PluginError, match="non-JSON response"):
            self.client.find_domain("example.com")

    def test_unexpected_json_success(self) -> None:
        self.rsps.get(self._url("/me/domains"), status=200, json=["unexpected"])

        with pytest.raises(errors.PluginError, match="Unexpected response"):
            self.client.find_domain("example.com")

    def test_get_nameserver_settings(self) -> None:
        settings = {"domain-id": self.domain_id, "setup-type": "muumuu_dns", "nameservers": []}
        self.rsps.get(
            self._url(f"/me/domains/{self.domain_id}/nameservers"), json={"data": settings}
        )

        assert self.client.get_nameserver_settings(self.domain_id) == settings

    def test_add_txt_record(self) -> None:
        self.rsps.post(
            self._url(f"/me/domains/{self.domain_id}/dns-records"),
            status=201,
            match=[
                matchers.json_params_matcher(
                    {"fqdn": self.record_name, "type": "TXT", "value": self.record_content},
                    strict_match=True,
                )
            ],
            json={"data": _txt(42, self.record_name + ".", self.record_content)},
        )

        assert (
            self.client.add_txt_record(self.domain_id, self.record_name, self.record_content) == 42
        )

    def test_add_txt_record_conflict_reuses_existing_record(self) -> None:
        self.rsps.post(
            self._url(f"/me/domains/{self.domain_id}/dns-records"),
            status=409,
            json={
                "error": {
                    "code": "conflict",
                    "message": "A record with the same fqdn, type, and value already exists",
                }
            },
        )
        self.rsps.get(
            self._url(f"/me/domains/{self.domain_id}/dns-records"),
            json=_records_page(
                [
                    _txt(1, self.record_name + ".", "other"),
                    _txt(2, self.record_name + ".", self.record_content),
                ],
                2,
            ),
        )

        assert (
            self.client.add_txt_record(self.domain_id, self.record_name, self.record_content) == 2
        )

    def test_add_txt_record_conflict_without_matching_record(self) -> None:
        self.rsps.post(
            self._url(f"/me/domains/{self.domain_id}/dns-records"),
            status=409,
            json={"error": {"code": "conflict", "message": "The resource already exists"}},
        )
        self.rsps.get(
            self._url(f"/me/domains/{self.domain_id}/dns-records"), json=_records_page([], 0)
        )

        with pytest.raises(errors.PluginError, match="HTTP 409 conflict"):
            self.client.add_txt_record(self.domain_id, self.record_name, self.record_content)

    def test_add_txt_record_limit_exceeded(self) -> None:
        self.rsps.post(
            self._url(f"/me/domains/{self.domain_id}/dns-records"),
            status=400,
            json={"error": {"code": "bad_request", "message": "Record limit exceeded"}},
        )

        with pytest.raises(errors.PluginError, match="Record limit exceeded"):
            self.client.add_txt_record(self.domain_id, self.record_name, self.record_content)

    def test_find_txt_record_ids_paginates_and_matches_by_value(self) -> None:
        url = self._url(f"/me/domains/{self.domain_id}/dns-records")
        base = {"type": "TXT", "fqdn": self.record_name + ".", "page-size": "100"}
        first = [_txt(i, self.record_name + ".", f"other-{i}") for i in range(1, 100)]
        first.append(_txt(100, self.record_name + ".", f'"{self.record_content}"'))
        self.rsps.get(
            url,
            match=[matchers.query_param_matcher({**base, "page": "1"})],
            json=_records_page(first, 102),
        )
        self.rsps.get(
            url,
            match=[matchers.query_param_matcher({**base, "page": "2"})],
            json=_records_page(
                [
                    _txt(101, "sub." + self.record_name + ".", self.record_content),
                    _txt(102, self.record_name.upper() + ".", self.record_content),
                ],
                102,
                page=2,
            ),
        )

        ids = self.client.find_txt_record_ids(self.domain_id, self.record_name, self.record_content)

        assert ids == [100, 102]

    def test_delete_record(self) -> None:
        self.rsps.delete(self._url(f"/me/domains/{self.domain_id}/dns-records/42"), status=204)

        self.client.delete_record(self.domain_id, 42)

    def test_delete_record_already_gone(self) -> None:
        self.rsps.delete(
            self._url(f"/me/domains/{self.domain_id}/dns-records/42"),
            status=404,
            json={"error": {"code": "not_found", "message": "Not found"}},
        )

        self.client.delete_record(self.domain_id, 42)

    def test_delete_record_error(self) -> None:
        self.rsps.delete(
            self._url(f"/me/domains/{self.domain_id}/dns-records/42"),
            status=500,
            json={"error": {"code": "internal_error", "message": "Internal error"}},
        )

        with pytest.raises(errors.PluginError, match="HTTP 500"):
            self.client.delete_record(self.domain_id, 42)

    def test_retries_after_rate_limit(self) -> None:
        url = self._url(f"/me/domains/{self.domain_id}/nameservers")
        self.rsps.get(url, status=429, headers={"Retry-After": "7"}, json={})
        self.rsps.get(url, status=429, headers={"Retry-After": "bogus"}, json={})
        self.rsps.get(url, json={"data": {"setup-type": "muumuu_dns"}})

        assert self.client.get_nameserver_settings(self.domain_id) == {"setup-type": "muumuu_dns"}
        assert self.sleep.call_args_list == [mock.call(7), mock.call(60)]

    def test_retry_after_http_date(self) -> None:
        url = self._url(f"/me/domains/{self.domain_id}/nameservers")
        when = datetime.now(timezone.utc) + timedelta(seconds=120)
        self.rsps.get(url, status=429, headers={"Retry-After": format_datetime(when, usegmt=True)})
        self.rsps.get(url, status=429, json={})
        self.rsps.get(url, json={"data": {}})

        self.client.get_nameserver_settings(self.domain_id)

        first, second = (c.args[0] for c in self.sleep.call_args_list)
        assert 100 <= first <= 120
        assert second == 60

    def test_retry_after_http_date_in_the_past(self) -> None:
        url = self._url(f"/me/domains/{self.domain_id}/nameservers")
        self.rsps.get(url, status=429, headers={"Retry-After": "Wed, 21 Oct 2015 07:28:00 -0000"})
        self.rsps.get(url, json={"data": {}})

        self.client.get_nameserver_settings(self.domain_id)

        assert self.sleep.call_args_list == [mock.call(1)]

    def test_gives_up_after_max_attempts(self) -> None:
        url = self._url(f"/me/domains/{self.domain_id}/nameservers")
        for _ in range(3):
            self.rsps.get(
                url,
                status=429,
                headers={"Retry-After": "1"},
                json={"error": {"code": "rate_limit_exceeded", "message": "Rate limit exceeded"}},
            )

        with pytest.raises(errors.PluginError, match="HTTP 429 rate_limit_exceeded"):
            self.client.get_nameserver_settings(self.domain_id)
        assert self.sleep.call_count == 2

    def test_does_not_wait_for_long_retry_after(self) -> None:
        self.rsps.get(
            self._url(f"/me/domains/{self.domain_id}/nameservers"),
            status=429,
            headers={"Retry-After": "3600"},
            json={},
        )

        with pytest.raises(errors.PluginError, match="HTTP 429"):
            self.client.get_nameserver_settings(self.domain_id)
        self.sleep.assert_not_called()

    def test_retries_server_errors_with_backoff(self) -> None:
        url = self._url(f"/me/domains/{self.domain_id}/nameservers")
        self.rsps.get(url, status=503, json={"error": {"code": "service_unavailable"}})
        self.rsps.get(url, status=502, body="Bad Gateway")
        self.rsps.get(url, json={"data": {"setup-type": "muumuu_dns"}})

        assert self.client.get_nameserver_settings(self.domain_id) == {"setup-type": "muumuu_dns"}
        assert self.sleep.call_args_list == [mock.call(1), mock.call(2)]

    def test_does_not_retry_client_errors(self) -> None:
        self.rsps.get(
            self._url(f"/me/domains/{self.domain_id}/nameservers"),
            status=404,
            json={"error": {"code": "not_found", "message": "Not found"}},
        )

        with pytest.raises(errors.PluginError, match="HTTP 404 not_found"):
            self.client.get_nameserver_settings(self.domain_id)
        self.sleep.assert_not_called()

    def test_retries_network_errors(self) -> None:
        url = self._url(f"/me/domains/{self.domain_id}/nameservers")
        self.rsps.get(url, body=requests.ConnectionError("connection reset"))
        self.rsps.get(url, body=requests.Timeout("read timed out"))
        self.rsps.get(url, json={"data": {"setup-type": "muumuu_dns"}})

        assert self.client.get_nameserver_settings(self.domain_id) == {"setup-type": "muumuu_dns"}
        assert self.sleep.call_count == 2

    def test_persistent_network_error(self) -> None:
        url = self._url(f"/me/domains/{self.domain_id}/nameservers")
        for _ in range(3):
            self.rsps.get(url, body=requests.ConnectionError("connection refused"))

        with pytest.raises(errors.PluginError, match="Network error.*connection refused"):
            self.client.get_nameserver_settings(self.domain_id)

    def test_other_request_errors_are_not_retried(self) -> None:
        self.rsps.get(
            self._url(f"/me/domains/{self.domain_id}/nameservers"),
            body=requests.TooManyRedirects("too many redirects"),
        )

        with pytest.raises(errors.PluginError, match="too many redirects"):
            self.client.get_nameserver_settings(self.domain_id)
        self.sleep.assert_not_called()

    def test_retried_post_that_succeeded_reuses_the_record(self) -> None:
        url = self._url(f"/me/domains/{self.domain_id}/dns-records")
        self.rsps.post(url, body=requests.ReadTimeout("read timed out"))
        self.rsps.post(
            url,
            status=409,
            json={"error": {"code": "conflict", "message": "already exists"}},
        )
        self.rsps.get(
            url, json=_records_page([_txt(5, self.record_name + ".", self.record_content)], 1)
        )

        assert (
            self.client.add_txt_record(self.domain_id, self.record_name, self.record_content) == 5
        )


if __name__ == "__main__":
    sys.exit(pytest.main(sys.argv[1:] + [__file__]))  # pragma: no cover
