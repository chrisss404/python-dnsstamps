
For general information about DNS stamps please visit https://dnscrypt.info/stamps-specifications

## Install

    python3 -m pip install --user dnsstamps


## Generate DNS stamps

### Plain

    $ dnsstamp.py plain -s -a 127.0.0.1
    Plain DNS stamp
    ===============
    
    DNSSEC: yes
    No logs: no
    No filter: no
    IP Address: 127.0.0.1
    
    Stamp: sdns://AAEAAAAAAAAACTEyNy4wLjAuMQ


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
    
    Stamp: sdns://AQEAAAAAAAAACTEyNy4wLjAuMSDLatxcKflVEAtlvxKU_laEV5qzSZzJeY8A0Bu1wamixxsyLmRuc2NyeXB0LWNlcnQuZXhhbXBsZS5jb20


### DNS over HTTPS

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
    Hashes: 3e1a1a0f6c53f3e97a492d57084b5b9807059ee057ab1505876fd83fda3db838
    Hostname: doh.example.com
    Path: /dns-query
    Bootstrap IPs: None
    
    Stamp: sdns://AgEAAAAAAAAACTEyNy4wLjAuMSA-GhoPbFPz6XpJLVcIS1uYBwWe4FerFQWHb9g_2j24OA9kb2guZXhhbXBsZS5jb20KL2Rucy1xdWVyeQ


### DNS over TLS

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
    Hashes: 2f1af500a66d4b83760766e41cb1123ebd6b95853afaef3bcdf39cbde3ab30b6
    Bootstrap IPs: None
    
    Stamp: sdns://AwEAAAAAAAAACTEyNy4wLjAuMSAvGvUApm1Lg3YHZuQcsRI-vWuVhTr67zvN85y946swtg9kb3QuZXhhbXBsZS5jb20


## Run tests

    python3 -m unittest discover


## Build and upload
    
    python3 setup.py sdist bdist_wheel
    python3 -m twine upload dist/*


