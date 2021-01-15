import unittest

import dnsstamps
from dnsstamps import Option
from dnsstamps import Protocol


class TestParser(unittest.TestCase):

    def test_parse_stamp_with_invalid_format(self):
        with self.assertRaises(Exception) as context:
            dnsstamps.parse("sdns://abc123xyz")
        self.assertEqual(
            "('Unable to unpack stamp', Error('Invalid base64-encoded string: number of data characters (9) cannot be 1 more than a multiple of 4'))",
            str(context.exception),
            "Invalid exception")

    def test_parse_stamp_with_invalid_protocol(self):
        with self.assertRaises(Exception) as context:
            dnsstamps.parse("sdns://abc123")
        self.assertEqual(
            "('Unable to consume protocol', ValueError('105 is not a valid Protocol'))",
            str(context.exception),
            "Invalid exception")

    def test_parse_plain_stamp(self):
        parameter = dnsstamps.parse("sdns://AAAAAAAAAAAAGltmZTgwOjo2ZDZkOmY3MmM6M2FkOjYwYjhd")

        self.assertEqual(Protocol.PLAIN, parameter.protocol, "Invalid protocol")
        self.assertEqual([], parameter.options, "Invalid options")
        self.assertEqual("[fe80::6d6d:f72c:3ad:60b8]", parameter.address, "Invalid address")

    def test_parse_plain_stamp_with_options(self):
        parameter = dnsstamps.parse("sdns://AAcAAAAAAAAACTEyNy4wLjAuMQ")

        self.assertEqual(Protocol.PLAIN, parameter.protocol, "Invalid protocol")
        self.assertEqual([Option.DNSSEC, Option.NO_LOGS, Option.NO_FILTERS], parameter.options, "Invalid options")
        self.assertEqual("127.0.0.1", parameter.address, "Invalid address")

    def test_parse_dnscrypt_stamp(self):
        parameter = dnsstamps.parse(
            "sdns://AQAAAAAAAAAAGltmZTgwOjo2ZDZkOmY3MmM6M2FkOjYwYjhdIMtq3Fwp-VUQC2W_EpT-VoRXmrNJnMl5jwDQG7XBqaLHGzIuZG5zY3J5cHQtY2VydC5leGFtcGxlLmNvbQ")

        self.assertEqual(Protocol.DNSCRYPT, parameter.protocol, "Invalid protocol")
        self.assertEqual([], parameter.options, "Invalid options")
        self.assertEqual("[fe80::6d6d:f72c:3ad:60b8]", parameter.address, "Invalid address")
        self.assertEqual(b"cb6adc5c29f955100b65bf1294fe5684579ab3499cc9798f00d01bb5c1a9a2c7", parameter.public_key,
                         "Invalid public_key")
        self.assertEqual("2.dnscrypt-cert.example.com", parameter.provider_name, "Invalid provider_name")

    def test_parse_dnscrypt_stamp_with_options(self):
        parameter = dnsstamps.parse(
            "sdns://AQUAAAAAAAAACTEyNy4wLjAuMSDLatxcKflVEAtlvxKU_laEV5qzSZzJeY8A0Bu1wamixxsyLmRuc2NyeXB0LWNlcnQuZXhhbXBsZS5jb20")

        self.assertEqual(Protocol.DNSCRYPT, parameter.protocol, "Invalid protocol")
        self.assertEqual([Option.DNSSEC, Option.NO_FILTERS], parameter.options, "Invalid options")
        self.assertEqual("127.0.0.1", parameter.address, "Invalid address")
        self.assertEqual(b"cb6adc5c29f955100b65bf1294fe5684579ab3499cc9798f00d01bb5c1a9a2c7", parameter.public_key,
                         "Invalid public_key")
        self.assertEqual("2.dnscrypt-cert.example.com", parameter.provider_name, "Invalid provider_name")

    def test_parse_doh_stamp(self):
        parameter = dnsstamps.parse(
            "sdns://AgAAAAAAAAAAGltmZTgwOjo2ZDZkOmY3MmM6M2FkOjYwYjhdID4aGg9sU_PpekktVwhLW5gHBZ7gV6sVBYdv2D_aPbg4D2RvaC5leGFtcGxlLmNvbQovZG5zLXF1ZXJ5")

        self.assertEqual(Protocol.DOH, parameter.protocol, "Invalid protocol")
        self.assertEqual([], parameter.options, "Invalid options")
        self.assertEqual("[fe80::6d6d:f72c:3ad:60b8]", parameter.address, "Invalid address")
        self.assertEqual([b"3e1a1a0f6c53f3e97a492d57084b5b9807059ee057ab1505876fd83fda3db838"], parameter.hashes,
                         "Invalid hashes")
        self.assertEqual("doh.example.com", parameter.hostname, "Invalid hostname")
        self.assertEqual("/dns-query", parameter.path, "Invalid path")
        self.assertEqual([], parameter.bootstrap_ips, "Invalid bootstrap_ips")

    def test_parse_doh_stamp_with_options(self):
        parameter = dnsstamps.parse(
            "sdns://AgYAAAAAAAAACTEyNy4wLjAuMSA-GhoPbFPz6XpJLVcIS1uYBwWe4FerFQWHb9g_2j24OA9kb2guZXhhbXBsZS5jb20KL2Rucy1xdWVyeQ")

        self.assertEqual(Protocol.DOH, parameter.protocol, "Invalid protocol")
        self.assertEqual([Option.NO_LOGS, Option.NO_FILTERS], parameter.options, "Invalid options")
        self.assertEqual("127.0.0.1", parameter.address, "Invalid address")
        self.assertEqual([b"3e1a1a0f6c53f3e97a492d57084b5b9807059ee057ab1505876fd83fda3db838"], parameter.hashes,
                         "Invalid hashes")
        self.assertEqual("doh.example.com", parameter.hostname, "Invalid hostname")
        self.assertEqual("/dns-query", parameter.path, "Invalid path")
        self.assertEqual([], parameter.bootstrap_ips, "Invalid bootstrap_ips")

    def test_parse_doh_stamp_with_multiple_hashes(self):
        parameter = dnsstamps.parse(
            "sdns://AgAAAAAAAAAACTEyNy4wLjAuMaA-GhoPbFPz6XpJLVcIS1uYBwWe4FerFQWHb9g_2j24OCDQskN3amwQ5EhbNOo-OzoGPzCJdw4Ep4yAh7fEnU-Y1g9kb2guZXhhbXBsZS5jb20KL2Rucy1xdWVyeQ")

        self.assertEqual(Protocol.DOH, parameter.protocol, "Invalid protocol")
        self.assertEqual([], parameter.options, "Invalid options")
        self.assertEqual("127.0.0.1", parameter.address, "Invalid address")
        self.assertEqual([b"3e1a1a0f6c53f3e97a492d57084b5b9807059ee057ab1505876fd83fda3db838",
                          b"d0b243776a6c10e4485b34ea3e3b3a063f3089770e04a78c8087b7c49d4f98d6"], parameter.hashes,
                         "Invalid hashes")
        self.assertEqual("doh.example.com", parameter.hostname, "Invalid hostname")
        self.assertEqual("/dns-query", parameter.path, "Invalid path")
        self.assertEqual([], parameter.bootstrap_ips, "Invalid bootstrap_ips")

    def test_parse_doh_stamp_with_bootstrap_ips(self):
        parameter = dnsstamps.parse(
            "sdns://AgAAAAAAAAAACTEyNy4wLjAuMSA-GhoPbFPz6XpJLVcIS1uYBwWe4FerFQWHb9g_2j24OA9kb2guZXhhbXBsZS5jb20KL2Rucy1xdWVyeQcxLjEuMS4x")

        self.assertEqual(Protocol.DOH, parameter.protocol, "Invalid protocol")
        self.assertEqual([], parameter.options, "Invalid options")
        self.assertEqual("127.0.0.1", parameter.address, "Invalid address")
        self.assertEqual([b"3e1a1a0f6c53f3e97a492d57084b5b9807059ee057ab1505876fd83fda3db838"], parameter.hashes,
                         "Invalid hashes")
        self.assertEqual("doh.example.com", parameter.hostname, "Invalid hostname")
        self.assertEqual("/dns-query", parameter.path, "Invalid path")
        self.assertEqual(["1.1.1.1"], parameter.bootstrap_ips, "Invalid bootstrap_ips")

    def test_parse_doh_stamp_without_hashes(self):
        parameter = dnsstamps.parse("sdns://AgUAAAAAAAAAAAAPZG9oLmV4YW1wbGUuY29tCi9kbnMtcXVlcnk")

        self.assertEqual(Protocol.DOH, parameter.protocol, "Invalid protocol")
        self.assertEqual([Option.DNSSEC, Option.NO_FILTERS], parameter.options, "Invalid options")
        self.assertEqual("", parameter.address, "Invalid address")
        self.assertEqual([], parameter.hashes, "Invalid hashes")
        self.assertEqual("doh.example.com", parameter.hostname, "Invalid hostname")
        self.assertEqual("/dns-query", parameter.path, "Invalid path")
        self.assertEqual([], parameter.bootstrap_ips, "Invalid bootstrap_ips")

    def test_parse_dot_stamp(self):
        parameter = dnsstamps.parse(
            "sdns://AwAAAAAAAAAAGltmZTgwOjo2ZDZkOmY3MmM6M2FkOjYwYjhdID4aGg9sU_PpekktVwhLW5gHBZ7gV6sVBYdv2D_aPbg4D2RvdC5leGFtcGxlLmNvbQ")

        self.assertEqual(Protocol.DOT, parameter.protocol, "Invalid protocol")
        self.assertEqual([], parameter.options, "Invalid options")
        self.assertEqual("[fe80::6d6d:f72c:3ad:60b8]", parameter.address, "Invalid address")
        self.assertEqual([b"3e1a1a0f6c53f3e97a492d57084b5b9807059ee057ab1505876fd83fda3db838"], parameter.hashes,
                         "Invalid hashes")
        self.assertEqual("dot.example.com", parameter.hostname, "Invalid hostname")
        self.assertEqual([], parameter.bootstrap_ips, "Invalid bootstrap_ips")

    def test_parse_dot_stamp_with_options(self):
        parameter = dnsstamps.parse(
            "sdns://AwEAAAAAAAAACTEyNy4wLjAuMSA-GhoPbFPz6XpJLVcIS1uYBwWe4FerFQWHb9g_2j24OA9kb3QuZXhhbXBsZS5jb20")

        self.assertEqual(Protocol.DOT, parameter.protocol, "Invalid protocol")
        self.assertEqual([Option.DNSSEC], parameter.options, "Invalid options")
        self.assertEqual("127.0.0.1", parameter.address, "Invalid address")
        self.assertEqual([b"3e1a1a0f6c53f3e97a492d57084b5b9807059ee057ab1505876fd83fda3db838"], parameter.hashes,
                         "Invalid hashes")
        self.assertEqual("dot.example.com", parameter.hostname, "Invalid hostname")
        self.assertEqual([], parameter.bootstrap_ips, "Invalid bootstrap_ips")

    def test_parse_dot_stamp_with_multiple_hashes(self):
        parameter = dnsstamps.parse(
            "sdns://AwAAAAAAAAAACTEyNy4wLjAuMaA-GhoPbFPz6XpJLVcIS1uYBwWe4FerFQWHb9g_2j24OCDQskN3amwQ5EhbNOo-OzoGPzCJdw4Ep4yAh7fEnU-Y1g9kb3QuZXhhbXBsZS5jb20")

        self.assertEqual(Protocol.DOT, parameter.protocol, "Invalid protocol")
        self.assertEqual([], parameter.options, "Invalid options")
        self.assertEqual("127.0.0.1", parameter.address, "Invalid address")
        self.assertEqual([b"3e1a1a0f6c53f3e97a492d57084b5b9807059ee057ab1505876fd83fda3db838",
                          b"d0b243776a6c10e4485b34ea3e3b3a063f3089770e04a78c8087b7c49d4f98d6"], parameter.hashes,
                         "Invalid hashes")
        self.assertEqual("dot.example.com", parameter.hostname, "Invalid hostname")
        self.assertEqual([], parameter.bootstrap_ips, "Invalid bootstrap_ips")

    def test_parse_dot_stamp_with_bootstrap_ips(self):
        parameter = dnsstamps.parse(
            "sdns://AwAAAAAAAAAACTEyNy4wLjAuMSA-GhoPbFPz6XpJLVcIS1uYBwWe4FerFQWHb9g_2j24OA9kb3QuZXhhbXBsZS5jb20HMS4xLjEuMQ")

        self.assertEqual(Protocol.DOT, parameter.protocol, "Invalid protocol")
        self.assertEqual([], parameter.options, "Invalid options")
        self.assertEqual("127.0.0.1", parameter.address, "Invalid address")
        self.assertEqual([b"3e1a1a0f6c53f3e97a492d57084b5b9807059ee057ab1505876fd83fda3db838"], parameter.hashes,
                         "Invalid hashes")
        self.assertEqual("dot.example.com", parameter.hostname, "Invalid hostname")
        self.assertEqual(["1.1.1.1"], parameter.bootstrap_ips, "Invalid bootstrap_ips")

    def test_parse_dot_stamp_without_hashes(self):
        parameter = dnsstamps.parse("sdns://AwUAAAAAAAAAAAAPZG90LmV4YW1wbGUuY29t")

        self.assertEqual(Protocol.DOT, parameter.protocol, "Invalid protocol")
        self.assertEqual([Option.DNSSEC, Option.NO_FILTERS], parameter.options, "Invalid options")
        self.assertEqual("", parameter.address, "Invalid address")
        self.assertEqual([], parameter.hashes, "Invalid hashes")
        self.assertEqual("dot.example.com", parameter.hostname, "Invalid hostname")
        self.assertEqual([], parameter.bootstrap_ips, "Invalid bootstrap_ips")

    def test_parse_doq_stamp(self):
        parameter = dnsstamps.parse(
            "sdns://BAAAAAAAAAAAGltmZTgwOjo2ZDZkOmY3MmM6M2FkOjYwYjhdID4aGg9sU_PpekktVwhLW5gHBZ7gV6sVBYdv2D_aPbg4D2RvcS5leGFtcGxlLmNvbQ")

        self.assertEqual(Protocol.DOQ, parameter.protocol, "Invalid protocol")
        self.assertEqual([], parameter.options, "Invalid options")
        self.assertEqual("[fe80::6d6d:f72c:3ad:60b8]", parameter.address, "Invalid address")
        self.assertEqual([b"3e1a1a0f6c53f3e97a492d57084b5b9807059ee057ab1505876fd83fda3db838"], parameter.hashes,
                         "Invalid hashes")
        self.assertEqual("doq.example.com", parameter.hostname, "Invalid hostname")
        self.assertEqual([], parameter.bootstrap_ips, "Invalid bootstrap_ips")

    def test_parse_doq_stamp_with_options(self):
        parameter = dnsstamps.parse(
            "sdns://BAEAAAAAAAAACTEyNy4wLjAuMSA-GhoPbFPz6XpJLVcIS1uYBwWe4FerFQWHb9g_2j24OA9kb3EuZXhhbXBsZS5jb20")

        self.assertEqual(Protocol.DOQ, parameter.protocol, "Invalid protocol")
        self.assertEqual([Option.DNSSEC], parameter.options, "Invalid options")
        self.assertEqual("127.0.0.1", parameter.address, "Invalid address")
        self.assertEqual([b"3e1a1a0f6c53f3e97a492d57084b5b9807059ee057ab1505876fd83fda3db838"], parameter.hashes,
                         "Invalid hashes")
        self.assertEqual("doq.example.com", parameter.hostname, "Invalid hostname")
        self.assertEqual([], parameter.bootstrap_ips, "Invalid bootstrap_ips")

    def test_parse_doq_stamp_with_multiple_hashes(self):
        parameter = dnsstamps.parse(
            "sdns://BAAAAAAAAAAACTEyNy4wLjAuMaA-GhoPbFPz6XpJLVcIS1uYBwWe4FerFQWHb9g_2j24OCDQskN3amwQ5EhbNOo-OzoGPzCJdw4Ep4yAh7fEnU-Y1g9kb3EuZXhhbXBsZS5jb20")

        self.assertEqual(Protocol.DOQ, parameter.protocol, "Invalid protocol")
        self.assertEqual([], parameter.options, "Invalid options")
        self.assertEqual("127.0.0.1", parameter.address, "Invalid address")
        self.assertEqual([b"3e1a1a0f6c53f3e97a492d57084b5b9807059ee057ab1505876fd83fda3db838",
                          b"d0b243776a6c10e4485b34ea3e3b3a063f3089770e04a78c8087b7c49d4f98d6"], parameter.hashes,
                         "Invalid hashes")
        self.assertEqual("doq.example.com", parameter.hostname, "Invalid hostname")
        self.assertEqual([], parameter.bootstrap_ips, "Invalid bootstrap_ips")

    def test_parse_doq_stamp_with_bootstrap_ips(self):
        parameter = dnsstamps.parse(
            "sdns://BAAAAAAAAAAACTEyNy4wLjAuMSA-GhoPbFPz6XpJLVcIS1uYBwWe4FerFQWHb9g_2j24OA9kb3EuZXhhbXBsZS5jb20HMS4xLjEuMQ")

        self.assertEqual(Protocol.DOQ, parameter.protocol, "Invalid protocol")
        self.assertEqual([], parameter.options, "Invalid options")
        self.assertEqual("127.0.0.1", parameter.address, "Invalid address")
        self.assertEqual([b"3e1a1a0f6c53f3e97a492d57084b5b9807059ee057ab1505876fd83fda3db838"], parameter.hashes,
                         "Invalid hashes")
        self.assertEqual("doq.example.com", parameter.hostname, "Invalid hostname")
        self.assertEqual(["1.1.1.1"], parameter.bootstrap_ips, "Invalid bootstrap_ips")

    def test_parse_doq_stamp_without_hashes(self):
        parameter = dnsstamps.parse("sdns://BAUAAAAAAAAAAAAPZG9xLmV4YW1wbGUuY29t")

        self.assertEqual(Protocol.DOQ, parameter.protocol, "Invalid protocol")
        self.assertEqual([Option.DNSSEC, Option.NO_FILTERS], parameter.options, "Invalid options")
        self.assertEqual("", parameter.address, "Invalid address")
        self.assertEqual([], parameter.hashes, "Invalid hashes")
        self.assertEqual("doq.example.com", parameter.hostname, "Invalid hostname")
        self.assertEqual([], parameter.bootstrap_ips, "Invalid bootstrap_ips")

    def test_parse_doh_target_stamp(self):
        parameter = dnsstamps.parse("sdns://BQAAAAAAAAAAFmRvaC10YXJnZXQuZXhhbXBsZS5jb20KL2Rucy1xdWVyeQ")

        self.assertEqual(Protocol.DOH_TARGET, parameter.protocol, "Invalid protocol")
        self.assertEqual([], parameter.options, "Invalid options")
        self.assertEqual("doh-target.example.com", parameter.hostname, "Invalid hostname")
        self.assertEqual("/dns-query", parameter.path, "Invalid path")

    def test_parse_doh_target_stamp_with_options(self):
        parameter = dnsstamps.parse("sdns://BQYAAAAAAAAAFmRvaC10YXJnZXQuZXhhbXBsZS5jb20KL2Rucy1xdWVyeQ")

        self.assertEqual(Protocol.DOH_TARGET, parameter.protocol, "Invalid protocol")
        self.assertEqual([Option.NO_LOGS, Option.NO_FILTERS], parameter.options, "Invalid options")
        self.assertEqual("doh-target.example.com", parameter.hostname, "Invalid hostname")
        self.assertEqual("/dns-query", parameter.path, "Invalid path")

    def test_parse_dnscrypt_relay_stamp(self):
        parameter = dnsstamps.parse("sdns://gQ0xMjcuMC4wLjE6NDQz")

        self.assertEqual(Protocol.DNSCRYPT_RELAY, parameter.protocol, "Invalid protocol")
        self.assertEqual("127.0.0.1:443", parameter.address, "Invalid address")

    def test_parse_doh_relay_stamp(self):
        parameter = dnsstamps.parse(
            "sdns://hQAAAAAAAAAAGltmZTgwOjo2ZDZkOmY3MmM6M2FkOjYwYjhdID4aGg9sU_PpekktVwhLW5gHBZ7gV6sVBYdv2D_aPbg4FWRvaC1yZWxheS5leGFtcGxlLmNvbQovZG5zLXF1ZXJ5")

        self.assertEqual(Protocol.DOH_RELAY, parameter.protocol, "Invalid protocol")
        self.assertEqual([], parameter.options, "Invalid options")
        self.assertEqual("[fe80::6d6d:f72c:3ad:60b8]", parameter.address, "Invalid address")
        self.assertEqual([b"3e1a1a0f6c53f3e97a492d57084b5b9807059ee057ab1505876fd83fda3db838"], parameter.hashes,
                         "Invalid hashes")
        self.assertEqual("doh-relay.example.com", parameter.hostname, "Invalid hostname")
        self.assertEqual("/dns-query", parameter.path, "Invalid path")
        self.assertEqual([], parameter.bootstrap_ips, "Invalid bootstrap_ips")

    def test_parse_doh_relay_stamp_with_options(self):
        parameter = dnsstamps.parse(
            "sdns://hQIAAAAAAAAACTEyNy4wLjAuMSA-GhoPbFPz6XpJLVcIS1uYBwWe4FerFQWHb9g_2j24OBVkb2gtcmVsYXkuZXhhbXBsZS5jb20KL2Rucy1xdWVyeQ")

        self.assertEqual(Protocol.DOH_RELAY, parameter.protocol, "Invalid protocol")
        self.assertEqual([Option.NO_LOGS], parameter.options, "Invalid options")
        self.assertEqual("127.0.0.1", parameter.address, "Invalid address")
        self.assertEqual([b"3e1a1a0f6c53f3e97a492d57084b5b9807059ee057ab1505876fd83fda3db838"], parameter.hashes,
                         "Invalid hashes")
        self.assertEqual("doh-relay.example.com", parameter.hostname, "Invalid hostname")
        self.assertEqual("/dns-query", parameter.path, "Invalid path")
        self.assertEqual([], parameter.bootstrap_ips, "Invalid bootstrap_ips")

    def test_parse_doh_relay_stamp_with_multiple_hashes(self):
        parameter = dnsstamps.parse(
            "sdns://hQAAAAAAAAAACTEyNy4wLjAuMaA-GhoPbFPz6XpJLVcIS1uYBwWe4FerFQWHb9g_2j24OCDQskN3amwQ5EhbNOo-OzoGPzCJdw4Ep4yAh7fEnU-Y1hVkb2gtcmVsYXkuZXhhbXBsZS5jb20KL2Rucy1xdWVyeQ")

        self.assertEqual(Protocol.DOH_RELAY, parameter.protocol, "Invalid protocol")
        self.assertEqual([], parameter.options, "Invalid options")
        self.assertEqual("127.0.0.1", parameter.address, "Invalid address")
        self.assertEqual([b"3e1a1a0f6c53f3e97a492d57084b5b9807059ee057ab1505876fd83fda3db838",
                          b"d0b243776a6c10e4485b34ea3e3b3a063f3089770e04a78c8087b7c49d4f98d6"], parameter.hashes,
                         "Invalid hashes")
        self.assertEqual("doh-relay.example.com", parameter.hostname, "Invalid hostname")
        self.assertEqual("/dns-query", parameter.path, "Invalid path")
        self.assertEqual([], parameter.bootstrap_ips, "Invalid bootstrap_ips")

    def test_parse_doh_relay_stamp_with_bootstrap_ips(self):
        parameter = dnsstamps.parse(
            "sdns://hQAAAAAAAAAACTEyNy4wLjAuMSA-GhoPbFPz6XpJLVcIS1uYBwWe4FerFQWHb9g_2j24OBVkb2gtcmVsYXkuZXhhbXBsZS5jb20KL2Rucy1xdWVyeQcxLjEuMS4x")

        self.assertEqual(Protocol.DOH_RELAY, parameter.protocol, "Invalid protocol")
        self.assertEqual([], parameter.options, "Invalid options")
        self.assertEqual("127.0.0.1", parameter.address, "Invalid address")
        self.assertEqual([b"3e1a1a0f6c53f3e97a492d57084b5b9807059ee057ab1505876fd83fda3db838"], parameter.hashes,
                         "Invalid hashes")
        self.assertEqual("doh-relay.example.com", parameter.hostname, "Invalid hostname")
        self.assertEqual("/dns-query", parameter.path, "Invalid path")
        self.assertEqual(["1.1.1.1"], parameter.bootstrap_ips, "Invalid bootstrap_ips")

    def test_parse_doh_relay_stamp_without_hashes(self):
        parameter = dnsstamps.parse("sdns://hQIAAAAAAAAAAAAVZG9oLXJlbGF5LmV4YW1wbGUuY29tCi9kbnMtcXVlcnk")

        self.assertEqual(Protocol.DOH_RELAY, parameter.protocol, "Invalid protocol")
        self.assertEqual([Option.NO_LOGS], parameter.options, "Invalid options")
        self.assertEqual("", parameter.address, "Invalid address")
        self.assertEqual([], parameter.hashes, "Invalid hashes")
        self.assertEqual("doh-relay.example.com", parameter.hostname, "Invalid hostname")
        self.assertEqual("/dns-query", parameter.path, "Invalid path")
        self.assertEqual([], parameter.bootstrap_ips, "Invalid bootstrap_ips")
