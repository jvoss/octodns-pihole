#
#
#

import json
from unittest.mock import Mock, call

import pytest
from conftest import MOCK_URL
from requests_mock import mock as requests_mock

from octodns_pihole import (
    PiholeClient,
    PiholeClientException,
    PiholeClientNotFound,
    PiholeClientUnauthorized,
)


class TestPiholeClient:
    client = PiholeClient(MOCK_URL, 'password')

    def test_authorization(self, mock_request):
        # Wrong credentials
        with requests_mock() as mock:
            mock.post(f"{MOCK_URL}/api/auth", status_code=401, json={})

            with pytest.raises(PiholeClientUnauthorized):
                self.client._authorize()

        # Unexpected response payload
        with requests_mock() as mock:
            mock.post(f"{MOCK_URL}/api/auth", status_code=200, json={})

            with pytest.raises(PiholeClientException):
                self.client._authorize()

        # Successful auth
        self.client._authorize()
        assert 'sid' in self.client._session.headers

    def test_request(self):
        # test not found
        with requests_mock() as mock:
            mock.get(f"{MOCK_URL}/notfound", status_code=404)
            with pytest.raises(PiholeClientNotFound):
                self.client._request('GET', '/notfound', auth_required=False)

        # test unauthorized
        with requests_mock() as mock:
            mock.get(f"{MOCK_URL}/unauthorized", status_code=401)
            with pytest.raises(PiholeClientUnauthorized):
                self.client._request(
                    'GET', '/unauthorized', auth_required=False
                )

    def test_add_cname_record(self):
        self.client._cname_cache = []

        # adds entry to cname cache
        self.client.add_cname_record('test.example.tld.', 'target.example.tld.')
        assert 1 == len(self.client._cname_cache)

        # does not duplicate entry in cname cache
        self.client.add_cname_record('test.example.tld.', 'target.example.tld.')
        assert 1 == len(self.client._cname_cache)

    def test_add_host_record(self):
        self.client._host_cache = []

        # adds entry to host cache
        self.client.add_host_record('1.1.1.1', 'target.example.tld.')
        assert 1 == len(self.client._host_cache)

        # does not duplicate entry in cname cache
        self.client.add_host_record('1.1.1.1', 'target.example.tld.')
        assert 1 == len(self.client._host_cache)

    def test_apply(self):
        # Simple apply test - real values are tested from the provider test
        orig_request = self.client._request

        resp = Mock()
        self.client._request = Mock(return_value=resp)

        # Reset caches
        self.client._cname_cache = []
        self.client._host_cache = []

        self.client.apply()

        self.client._request.assert_has_calls(
            [
                call(
                    'PATCH',
                    '/api/config',
                    data={'config': {'dns': {'cnameRecords': [], 'hosts': []}}},
                )
            ]
        )

        # remove the mock on _request
        self.client._request = orig_request

    def test_delete_cname_record(self):
        self.client._cname_cache = ['cname.example.tld.,target.example.tld.']

        # valid delete
        self.client.delete_cname_record(
            'cname.example.tld.', 'target.example.tld.'
        )
        assert 0 == len(self.client._cname_cache)

        # ignores errors when already deleted
        self.client.delete_cname_record(
            'cname.example.tld.', 'target.example.tld.'
        )
        assert True  # Nothing should raise here

    def test_delete_host_record(self):
        self.client._host_cache = ['1.1.1.1 test.example.tld.']

        # valid delete
        self.client.delete_host_record('1.1.1.1', 'test.example.tld.')
        assert 0 == len(self.client._host_cache)

        # ignores errors when already deleted
        self.client.delete_host_record('1.1.1.1', 'test.example.tld.')
        assert True  # Nothing should raise here

    def test_get_cname_records(self, mock_request):
        with open('tests/fixtures/cnameRecords.json') as fh:
            fixture = json.load(fh)

        # valid response
        mock_request.get(
            f"{MOCK_URL}/api/config/dns/cnameRecords", json=fixture
        )
        assert (
            self.client.get_cname_records()
            == fixture["config"]["dns"]["cnameRecords"]
        )

        # unexpected response
        with pytest.raises(PiholeClientException):
            mock_request.get(f"{MOCK_URL}/api/config/dns/cnameRecords", json={})
            self.client.get_cname_records()

    def test_get_host_records(self, mock_request):
        with open('tests/fixtures/hosts.json') as fh:
            fixture = json.load(fh)

        # valid response
        mock_request.get(f"{MOCK_URL}/api/config/dns/hosts", json=fixture)
        assert (
            self.client.get_host_records() == fixture["config"]["dns"]["hosts"]
        )

        # unexpected response
        with pytest.raises(PiholeClientException):
            mock_request.get(f"{MOCK_URL}/api/config/dns/hosts", json={})
            self.client.get_host_records()
