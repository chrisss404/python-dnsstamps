
For general information about DNS stamps, see https://dnscrypt.info/stamps-specifications

## Installation

    python3 -m pip install --user dnsstamps


## Generating DNS stamps

### DNSCrypt

First get the public key, if you use dnsdist, you can get it in this way  

    > printDNSCryptProviderFingerprint("/path/to/your/providerPublic.key")
    Provider fingerprint is: CB6A:DC5C:29F9:5510:0B65:BF12:94FE:5684:579A:B349:9CC9:798F:00D0:1BB5:C1A9:A2C7

Then run

    $ dnsstamp.py dnscrypt -s -a 127.0.0.1 -n 2.dnscrypt-cert.example.com -k CB6A:DC5C:29F9:5510:0B65:BF12:94FE:5684:579A:B349:9CC9:798F:00D0:1BB5:C1A9:A2C7
    DNSCrypt DNS stamp
    ==================
    
    DNSSEC: yes
    No logs: no
    No filter: no
    IP Address: 127.0.0.1
    Public key: CB6A:DC5C:29F9:5510:0B65:BF12:94FE:5684:579A:B349:9CC9:798F:00D0:1BB5:C1A9:A2C7
    Provider name: 2.dnscrypt-cert.example.com
    
    sdns://AQEAAAAAAAAACTEyNy4wLjAuMSDLatxcKflVEAtlvxKU_laEV5qzSZzJeY8A0Bu1wamixxsyLmRuc2NyeXB0LWNlcnQuZXhhbXBsZS5jb20


### DNS-over-HTTPS

First get your certificate's signed data hash (tbsCertificate)

    $ openssl asn1parse -in doh.example.com.chain.pem -out /dev/stdout -noout -strparse 4 | openssl dgst -sha256
    (stdin)= 3e1a1a0f6c53f3e97a492d57084b5b9807059ee057ab1505876fd83fda3db838

Then run

    $ dnsstamp.py doh -s -a 127.0.0.1 -n doh.example.com -p /dns-query -t 3e1a1a0f6c53f3e97a492d57084b5b9807059ee057ab1505876fd83fda3db838
    DoH DNS stamp
    =============
    
    DNSSEC: yes
    No logs: no
    No filter: no
    IP Address: 127.0.0.1
    Hashes: ['3e1a1a0f6c53f3e97a492d57084b5b9807059ee057ab1505876fd83fda3db838']
    Hostname: doh.example.com
    Path: /dns-query
    Bootstrap IPs: []
    
    sdns://AgEAAAAAAAAACTEyNy4wLjAuMSA-GhoPbFPz6XpJLVcIS1uYBwWe4FerFQWHb9g_2j24OA9kb2guZXhhbXBsZS5jb20KL2Rucy1xdWVyeQ


### DNS-over-TLS

First get your certificate's signed data hash (tbsCertificate)

    $ openssl asn1parse -in dot.example.com.chain.pem -out /dev/stdout -noout -strparse 4 | openssl dgst -sha256
    (stdin)= 2f1af500a66d4b83760766e41cb1123ebd6b95853afaef3bcdf39cbde3ab30b6

Then run

    $ dnsstamp.py dot -s -a 127.0.0.1 -n dot.example.com -t 2f1af500a66d4b83760766e41cb1123ebd6b95853afaef3bcdf39cbde3ab30b6
    DoT DNS stamp
    =============
    
    DNSSEC: yes
    No logs: no
    No filter: no
    IP Address: 127.0.0.1
    Hostname: dot.example.com
    Hashes: ['2f1af500a66d4b83760766e41cb1123ebd6b95853afaef3bcdf39cbde3ab30b6']
    Bootstrap IPs: []
    
    sdns://AwEAAAAAAAAACTEyNy4wLjAuMSAvGvUApm1Lg3YHZuQcsRI-vWuVhTr67zvN85y946swtg9kb3QuZXhhbXBsZS5jb20


### DNS-over-QUIC

First get your certificate's signed data hash (tbsCertificate)

    $ openssl asn1parse -in doq.example.com.chain.pem -out /dev/stdout -noout -strparse 4 | openssl dgst -sha256
    (stdin)= 2449d49a44b91e80e0c71eeab76627579b6d4e53b4445cd5479004cc93d23263

Then run

    $ dnsstamp.py doq -s -a 127.0.0.1 -n doq.example.com -t 2449d49a44b91e80e0c71eeab76627579b6d4e53b4445cd5479004cc93d23263
    DoQ DNS stamp
    =============
    
    DNSSEC: yes
    No logs: no
    No filter: no
    IP Address: 127.0.0.1
    Hostname: doq.example.com
    Hashes: ['2449d49a44b91e80e0c71eeab76627579b6d4e53b4445cd5479004cc93d23263']
    Bootstrap IPs: []
    
    sdns://BAEAAAAAAAAACTEyNy4wLjAuMSAkSdSaRLkegODHHuq3ZidXm21OU7REXNVHkATMk9IyYw9kb3EuZXhhbXBsZS5jb20


### Oblivious DoH target

    $ dnsstamp.py doh_target -s -a 127.0.0.1 -n doh-target.example.com -p /dns-query
    DoH Target DNS stamp
    ====================
    
    DNSSEC: yes
    No logs: no
    No filter: no
    Hostname: doh-target.example.com
    Path: /dns-query
    
    sdns://BQEAAAAAAAAAFmRvaC10YXJnZXQuZXhhbXBsZS5jb20KL2Rucy1xdWVyeQ


### Anonymized DNSCrypt relay

    $ dnsstamp.py dnscrypt_relay -a 127.0.0.1
    DNSCrypt DNS Relay Stamp
    ========================
    
    IP Address: 127.0.0.1
    
    sdns://gQkxMjcuMC4wLjE


### Oblivious DoH relay

First get your certificate's signed data hash (tbsCertificate)

    $ openssl asn1parse -in doh.example.com.chain.pem -out /dev/stdout -noout -strparse 4 | openssl dgst -sha256
    (stdin)= 3e1a1a0f6c53f3e97a492d57084b5b9807059ee057ab1505876fd83fda3db838

Then run

    $ dnsstamp.py doh_relay -a 127.0.0.1 -n doh-relay.example.com -p /dns-query -t 3e1a1a0f6c53f3e97a492d57084b5b9807059ee057ab1505876fd83fda3db838
    DoH Relay DNS stamp
    ===================
    
    DNSSEC: no
    No logs: no
    No filter: no
    IP Address: 127.0.0.1
    Hashes: ['3e1a1a0f6c53f3e97a492d57084b5b9807059ee057ab1505876fd83fda3db838']
    Hostname: doh-relay.example.com
    Path: /dns-query
    Bootstrap IPs: []
    
    sdns://hQAAAAAAAAAACTEyNy4wLjAuMSA-GhoPbFPz6XpJLVcIS1uYBwWe4FerFQWHb9g_2j24OBVkb2gtcmVsYXkuZXhhbXBsZS5jb20KL2Rucy1xdWVyeQ


### Plain DNS

    $ dnsstamp.py plain -s -a 127.0.0.1
    Plain DNS stamp
    ===============
    
    DNSSEC: yes
    No logs: no
    No filter: no
    IP Address: 127.0.0.1
    
    sdns://AAEAAAAAAAAACTEyNy4wLjAuMQ


## Parsing DNS stamps

    $ dnsstamp.py parse sdns://AAEAAAAAAAAACTEyNy4wLjAuMQ
    Plain DNS stamp
    ===============
    
    DNSSEC: yes
    No logs: no
    No filter: no
    IP Address: 127.0.0.1
    
    sdns://AAEAAAAAAAAACTEyNy4wLjAuMQ


## Using the library
    
    import dnsstamps
    from dnsstamps import Option

    # DNSCrypt
    stamp = dnsstamps.create_dnscrypt("127.0.0.1", "CB6A:DC5C", "provider-name", [Option.DNSSEC])
    
    # DNS-over-HTTPS
    stamp = dnsstamps.create_doh("127.0.0.1", ["3e1a1a0f"], "hostname", "path", [Option.NO_LOGS])
    
    # DNS-over-TLS
    stamp = dnsstamps.create_dot("127.0.0.1", ["d0b24377"], "hostname", [Option.NO_FILTERS])

    # DNS-over-QUIC
    stamp = dnsstamps.create_doq("127.0.0.1", ["e50ff421"], "hostname", [Option.NO_FILTERS])

    # Oblivious DoH target
    stamp = dnsstamps.create_doh_target("hostname", "path", [Option.NO_LOGS])

    # Anonymized DNSCrypt relay
    stamp = dnsstamps.create_dnscrypt_relay("127.0.0.1")
  
    # Oblivious DoH relay
    stamp = dnsstamps.create_doh_relay("127.0.0.1", ["3e1a1a0f"], "hostname", "path", [Option.NO_LOGS])

    # Plain DNS
    stamp = dnsstamps.create_plain("127.0.0.1", [Option.DNSSEC, Option.NO_LOGS, Option.NO_FILTERS])

    # Parse
    parameter = dnsstamps.parse("sdns://AAEAAAAAAAAACTEyNy4wLjAuMQ")
    dnsstamps.format(parameter)
    stamp = dnsstamps.build(parameter)


## Running tests

    python3 -m unittest discover


## Setting up your own DNS server

* [Unbound](https://github.com/jedisct1/dnscrypt-proxy/wiki/How-to-setup-your-own-DNSCrypt-server-in-less-than-10-minutes) (DNSSEC, DNSCrypt)
* [PowerDNS](https://github.com/chrisss404/powerdns#private-recursor) (DNSSEC, DNSCrypt, DoH, DoT, Authoritative Server)


## Updating PyPI package
    
    python3 setup.py sdist bdist_wheel
    python3 -m twine upload dist/*


