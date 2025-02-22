#
#
#

import logging
from collections import defaultdict
from ipaddress import ip_address

from requests import Session

from octodns import __VERSION__ as octodns_version
from octodns.provider import ProviderException
from octodns.provider.base import BaseProvider
from octodns.record import Record

# TODO: remove __VERSION__ with the next major version release
__version__ = __VERSION__ = '0.0.1'


class PiholeClientException(ProviderException):
    pass


class PiholeClientNotFound(PiholeClientException):
    def __init__(self):
        super().__init__('Not Found')


class PiholeClientUnauthorized(PiholeClientException):
    def __init__(self):
        super().__init__('Unauthorized')


class PiholeClient(object):
    def __init__(self, url, password, totp=None, tls_verify=True):
        session = Session()
        session.verify = tls_verify

        session.headers.update(
            {
                'accept': 'application/json',
                'User-Agent': f'octodns/{octodns_version} octodns-pihole/{__VERSION__}',
            }
        )

        self._password = password
        self._session = session
        self._totp = totp
        self._url = url

        self._cname_cache = []
        self._host_cache = []

    def _authorize(self):
        path = "/api/auth"

        data = self._request(
            'POST',
            path,
            data={"password": self._password, "totp": self._totp},
            auth_required=False,
        ).json()
        try:
            self._session.headers["sid"] = data["session"]["sid"]
        except KeyError:
            raise PiholeClientException('Unexpected authorization response')

    def _request(
        self, method, path, params=None, data=None, auth_required=True
    ):
        if auth_required:
            self._authorize()

        url = f"{self._url}{path}"
        resp = self._session.request(method, url, params=params, json=data)

        match resp.status_code:
            case 401:
                raise PiholeClientUnauthorized()
            case 404:
                raise PiholeClientNotFound()

        resp.raise_for_status()
        return resp

    def add_cname_record(self, name, target):
        entry = f"{name},{target}"

        # avoid duplication
        if not entry in self._cname_cache:
            self._cname_cache.append(entry)

    def add_host_record(self, ip, name):
        entry = f"{ip} {name}"

        # avoid duplication
        if not entry in self._host_cache:
            self._host_cache.append(entry)

    def apply(self):
        """Applies the cache updates to Pi-Hole"""
        path = "/api/config"

        payload = {
            "config": {
                "dns": {
                    "cnameRecords": self._cname_cache,
                    "hosts": self._host_cache,
                }
            }
        }

        self._request('PATCH', path, data=payload)

    def delete_cname_record(self, name, target):
        try:
            self._cname_cache.remove(f"{name},{target}")
        except ValueError:
            pass

    def delete_host_record(self, ip, name):
        try:
            self._host_cache.remove(f"{ip} {name}")
        except ValueError:
            pass

    def get_cname_records(self):
        path = "/api/config/dns/cnameRecords"

        resp = self._request('GET', path).json()
        try:
            self._cname_cache = resp["config"]["dns"]["cnameRecords"]
        except KeyError:
            raise PiholeClientException('Unexpected response gathering CNAMEs')

        return self._cname_cache.copy()

    def get_host_records(self):
        path = "/api/config/dns/hosts"

        resp = self._request('GET', path).json()
        try:
            self._host_cache = resp["config"]["dns"]["hosts"]
        except KeyError:
            raise PiholeClientException('Unexpected response gathering hosts')

        return self._host_cache.copy()


class PiholeProvider(BaseProvider):
    DEFAULT_TTL = 86400  # TTL does not matter/unsupported for Pi-hole

    SUPPORTS_GEO = False
    SUPPORTS_DYNAMIC = False
    SUPPORTS_ROOT_NS = False
    SUPPORTS = set(('A', 'AAAA', 'CNAME'))

    def __init__(
        self, id, url, password, tls_verify=True, totp=None, *args, **kwargs
    ):
        self.log = logging.getLogger(f'PiholeProvider[{id}]')
        self.log.debug(
            '__init__: id=%s, url=%s tls_verify=%s', id, url, tls_verify
        )
        super().__init__(id, *args, **kwargs)
        self._client = PiholeClient(url, password, totp, tls_verify)

    def _data_for_multiple(self, type, records):
        return {
            'ttl': PiholeProvider.DEFAULT_TTL,
            'type': type,
            'values': [r for r in records],
        }

    _data_for_A = _data_for_multiple
    _data_for_AAAA = _data_for_multiple

    def _data_for_CNAME(self, _type, records):
        record = records[0]
        return {
            'ttl': PiholeProvider.DEFAULT_TTL,
            'type': _type,
            'value': f'{record}',
        }

    def _process_desired_zone(self, desired):
        # TTL is not supported for records in Pi-hole.
        # Reset desired records TTL to a known default to
        # ignore the source provider and prevent false changes.
        for record in desired.records:
            record = record.copy()
            record.ttl = PiholeProvider.DEFAULT_TTL
            desired.add_record(record, replace=True)

        return super()._process_desired_zone(desired)

    def populate(self, zone, target=False, lenient=False):
        self.log.debug(
            'populate: name=%s, target=%s, lenient=%s',
            zone.name,
            target,
            lenient,
        )

        values = defaultdict(lambda: defaultdict(list))

        # A/AAAA "records"
        for entry in self._client.get_host_records():
            ip, name = entry.split(' ', 1)

            # Pi-hole does not really have the concept of zones
            # we only want to return "records" within the zone
            if zone.name not in name:
                continue

            # Strip the zone name from the list entry
            name = name.split(zone.name, 1)[0].rstrip('.')

            match ip_address(ip).version:
                case 4:
                    values[name]['A'].append(ip)
                case 6:  # pragma: no cover (this is tested but coverage warns)
                    values[name]['AAAA'].append(ip)

        # CNAME "records"
        for entry in self._client.get_cname_records():
            name, target = entry.split(',', 1)

            # Pi-hole does not really have the concept of zones
            # we only want to return "records" within the zone
            if zone.name not in name:
                continue

            # Strip the zone name from the list entry
            name = name.split(f".{zone.name}", 1)[0]
            values[name]['CNAME'].append(target)

        before = len([r for r in values.values()])
        for name, types in values.items():
            for _type, records in types.items():
                data_for = getattr(self, f'_data_for_{_type}')
                record = Record.new(
                    zone,
                    name,
                    data_for(_type, records),
                    source=self,
                    lenient=lenient,
                )
                zone.add_record(record, lenient=lenient)

        exists = len(values) > 0
        self.log.info(
            'populate:   found %s records, exists=%s',
            len(zone.records) - before,
            exists,
        )
        return exists

    def _params_for_multiple(self, record):
        for value in record.values:
            yield {
                'name': (
                    f"{record.name}.{record.zone.name}"
                    if record.name
                    else record.zone.name
                ),
                'data': value,
            }

    _params_for_A = _params_for_multiple
    _params_for_AAAA = _params_for_multiple

    def _params_for_single(self, record):
        yield {
            'name': (
                f"{record.name}.{record.zone.name}"
                if record.name
                else record.zone.name
            ),
            'data': record.value,
        }

    _params_for_CNAME = _params_for_single

    def _apply_Create(self, change):
        new = change.new
        params_for = getattr(self, f'_params_for_{new._type}')
        for params in params_for(new):
            match change.record._type:
                case 'A' | 'AAAA':
                    self._client.add_host_record(params['data'], params['name'])
                case (
                    'CNAME'
                ):  # pragma: no cover (this is tested but coverage warns)
                    self._client.add_cname_record(
                        params['name'], params['data']
                    )

    def _apply_Update(self, change):
        self._apply_Delete(change)
        self._apply_Create(change)

    def _apply_Delete(self, change):
        existing = change.existing
        params_for = getattr(self, f'_params_for_{existing._type}')
        for params in params_for(existing):
            match change.record._type:
                case 'A' | 'AAAA':
                    self._client.delete_host_record(
                        params['data'], params['name']
                    )
                case (
                    'CNAME'
                ):  # pragma: no cover (this is tested but coverage warns)
                    self._client.delete_cname_record(
                        params['name'], params['data']
                    )

    def _apply(self, plan):
        desired = plan.desired
        changes = plan.changes
        self.log.debug(
            '_apply: zone=%s, len(changes)=%d', desired.name, len(changes)
        )

        for change in changes:
            class_name = change.__class__.__name__
            getattr(self, f'_apply_{class_name}')(change)

        self.log.info('_apply: sending changes to Pi-hole')

        self._client.apply()
