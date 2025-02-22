#
#
#

import json
from os.path import dirname, join
from unittest.mock import Mock, call

import pytest
from conftest import MOCK_URL
from requests import HTTPError
from requests_mock import ANY

from octodns.provider.yaml import YamlProvider
from octodns.record import Record
from octodns.zone import Zone

from octodns_pihole import PiholeProvider


class TestPiholeProvider:
    expected = Zone('unit.tests.', [])
    source = YamlProvider('test', join(dirname(__file__), 'config'))
    source.populate(expected)

    def test_populate(self, mock_request):
        provider = PiholeProvider('test', MOCK_URL, 'password')

        # Bad auth
        mock_request.get(
            ANY,
            status_code=401,
            json={
                "session": {
                    "valid": False,
                    "totp": False,
                    "sid": None,
                    "validity": -1,
                    "message": "password incorrect",
                },
                "took": 0.03502821922302246,
            },
        )

        with pytest.raises(Exception) as ctx:
            zone = Zone('unit.tests.', [])
            provider.populate(zone)
        assert 'Unauthorized' == str(ctx.value)

        # General error
        mock_request.get(ANY, status_code=502, text='Things caught fire')
        with pytest.raises(HTTPError) as ctx:
            zone = Zone('unit.tests.', [])
            provider.populate(zone)
        assert 502 == ctx.value.response.status_code

        # Non-existent zone doesn't populate anything
        mock_request.get(
            ANY,
            status_code=200,
            json={"config": {"dns": {"cnameRecords": [], "hosts": []}}},
        )

        zone = Zone('unit.tests.', [])
        provider.populate(zone)
        assert set() == zone.records

        # No diffs == no changes
        with open('tests/fixtures/cnameRecords.json') as fh:
            url = f"{MOCK_URL}/api/config/dns/cnameRecords"
            mock_request.get(url, json=json.load(fh))

        with open('tests/fixtures/hosts.json') as fh:
            url = f"{MOCK_URL}/api/config/dns/hosts"
            mock_request.get(url, json=json.load(fh))

        zone = Zone('unit.tests.', [])
        provider.populate(zone)
        # 5 supported records in unit.tests fixture
        assert 5 == len(zone.records)

        changes = self.expected.changes(zone, provider)
        assert 6 == len(changes)  # TODO - understand why this is 6??

    def test_apply(self):
        provider = PiholeProvider(
            'test', MOCK_URL, 'password', strict_supports=False
        )

        resp = Mock()
        resp.json.return_value = {
            "config": {"dns": {"cnameRecords": [], "hosts": []}}
        }
        provider._client._request = Mock(return_value=resp)

        plan = provider.plan(self.expected)

        # No ignored, no excluded, no unsupported
        n = len(self.expected.records) - 17
        assert n == len(plan.changes)
        assert n == provider.apply(plan)
        assert not plan.exists

        provider._client._request.assert_has_calls(
            [
                # get all current hosts
                call('GET', '/api/config/dns/hosts'),
                # get all current CNAMEs
                call('GET', '/api/config/dns/cnameRecords'),
                # applies the updated hosts/CNAMEs
                call(
                    'PATCH',
                    '/api/config',
                    data={
                        'config': {
                            'dns': {
                                'cnameRecords': [
                                    'cname.unit.tests.,unit.tests.',
                                    'included.unit.tests.,unit.tests.',
                                ],
                                'hosts': [
                                    '1.2.3.4 unit.tests.',
                                    '1.2.3.5 unit.tests.',
                                    '2601:644:500:e210:62f8:1dff:feb8:947a aaaa.unit.tests.',
                                    '2.2.3.6 www.unit.tests.',
                                    '2.2.3.6 www.sub.unit.tests.',
                                ],
                            }
                        }
                    },
                ),
            ]
        )
        assert 3 == provider._client._request.call_count

        # reset mock
        provider._client._request.reset_mock()
        # reset client caches
        provider._client._cname_cache = [
            "dont-touch-me.other.tld.,target.other.tld.",
            "delete-me.unit.tests.,target.unit.tests.",
        ]
        provider._client._host_cache = [
            "1.0.0.0 dont-touch-me.other.tld.",
            "1.1.1.1 delete-me.unit.tests.",
            "1.2.3.4 update-me.unit.tests.",
        ]

        # delete 2 and update 1
        provider._client.get_cname_records = Mock(
            return_value=provider._client._cname_cache
        )
        provider._client.get_host_records = Mock(
            return_value=provider._client._host_cache
        )

        wanted = Zone('unit.tests.', [])
        wanted.add_record(
            Record.new(
                wanted,
                'update-me',
                {'ttl': 300, 'type': 'A', 'value': '3.2.3.4'},
            )
        )

        plan = provider.plan(wanted)
        assert plan.exists
        assert 3 == len(plan.changes)
        assert 3 == provider.apply(plan)

        # expected update calls
        provider._client._request.assert_has_calls(
            [
                # applies the updated hosts/CNAMEs
                call(
                    'PATCH',
                    '/api/config',
                    data={
                        'config': {
                            'dns': {
                                'cnameRecords': [
                                    "dont-touch-me.other.tld.,target.other.tld."
                                ],
                                'hosts': [
                                    "1.0.0.0 dont-touch-me.other.tld.",
                                    "3.2.3.4 update-me.unit.tests.",
                                ],
                            }
                        }
                    },
                )
            ]
        )
        assert 1 == provider._client._request.call_count
