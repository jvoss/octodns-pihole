## Pi-hole provider for octoDNS

An [octoDNS](https://github.com/octodns/octodns/) provider that targets 
[Pi-hole](https://docs.pi-hole.net).

Pi-hole version 6 is supported.

In reality this provider manages matching A/AAAA/CNAME records with Pi-hole's
`Local DNS Records`. It will manage host and CNAME entries that match
domain names under management by OctoDNS. Other existing Pi-hole entries are
untouched.

TTL values are unsupported on host records and currently ignored for CNAMEs
records.

### Installation

#### Command line

```
pip install octodns-pihole
```

#### requirements.txt/setup.py

Pinning specific versions or SHAs is recommended to avoid unplanned upgrades.

##### Versions

```
# Start with the latest versions and don't just copy what's here
octodns==0.9.14
octodns-pihole==0.0.1
```

##### SHAs

```
# Start with the latest/specific versions and don't just copy what's here
-e git+https://git@github.com/octodns/octodns.git@9da19749e28f68407a1c246dfdf65663cdc1c422#egg=octodns
-e git+https://git@github.com/octodns/octodns-pihole.git@ec9661f8b335241ae4746eea467a8509205e6a30#egg=octodns_pihole
```

### Configuration

```yaml
providers:
  pihole:
    class: octodns_pihole.PiholeProvider
    url: https://pihole.lan:443
    password: env/PIHOLE_PASSWORD
    totp: env/PIHOLE_TOTP  # optional - required when 2FA is enabled
    tls_verify: false      # optional - default true
    strict_supports: false # ignore unsupported records
```

### Support Information

#### Records

Pi-Hole supports A, AAAA, and CNAME. PTR records will automatically exist for
A and AAAA records.

#### Dynamic

PiholeProvider does not support dynamic records.

### Development

See the [/script/](/script/) directory for some tools to help with the 
development process. They generally follow the 
[Script to rule them all](https://github.com/github/scripts-to-rule-them-all) 
pattern. Most useful is `./script/bootstrap` which will create a venv and 
install both the runtime and development related requirements. It will also hook
up a pre-commit hook that covers most of what's run by CI.

There is a [docker-compose.yml](docker-compose.yml) file included in the repo
that will set up a Pi-hole server with the API enabled for use in development.
The admin password/api-key for it is `correct horse battery staple`.

A configuration [example](example/) is provided and can be used along with the
[docker-compose.yml](docker-compose.yml):

1. Launch the container.

        docker compose up

    * Admin UI: http://localhost/admin
    * API Docs: http://localhost/api/docs

2. Run octodns-sync against the container

        octodns-sync --config-file=./example/config.yaml

3. Synchronize changes with Pi-hole

        octodns-sync --config-file=./example/config.yaml --doit

4. View records within the admin UI: 
   [Local DNS Records](http://localhost/admin/settings/dnsrecords)
