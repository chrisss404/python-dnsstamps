import unittest

import dnsstamps
from dnsstamps import Option
from dnsstamps import Parameter


class TestGenerator(unittest.TestCase):

    def test_build_with_invalid_parameter_type(self):
        with self.assertRaises(Exception) as context:
            dnsstamps.build(None)
        self.assertEqual(
            "Invalid parameter type <class 'NoneType'>",
            str(context.exception),
            "Invalid parameter type")

    def test_build_with_empty_parameters(self):
        self.assertEqual(
            "sdns://AAAAAAAAAAAACTEyNy4wLjAuMQ",
            dnsstamps.build(Parameter()),
            "Invalid stamp")

    def test_generate_plain_stamp(self):
        address = "[fe80::6d6d:f72c:3ad:60b8]"
        self.assertEqual(
            "sdns://AAAAAAAAAAAAGltmZTgwOjo2ZDZkOmY3MmM6M2FkOjYwYjhd",
            dnsstamps.create_plain(address),
            "Invalid stamp")

    def test_generate_plain_stamp_with_options(self):
        address = "127.0.0.1"
        options = [Option.DNSSEC, Option.NO_LOGS, Option.NO_FILTERS]
        self.assertEqual(
            "sdns://AAcAAAAAAAAACTEyNy4wLjAuMQ",
            dnsstamps.create_plain(address, options),
            "Invalid stamp")

    def test_generate_dnscrypt_stamp(self):
        address = "[fe80::6d6d:f72c:3ad:60b8]"
        public_key = "CB6A:DC5C:29F9:5510:0B65:BF12:94FE:5684:579A:B349:9CC9:798F:00D0:1BB5:C1A9:A2C7"
        provider_name = "2.dnscrypt-cert.example.com"

        self.assertEqual(
            "sdns://AQAAAAAAAAAAGltmZTgwOjo2ZDZkOmY3MmM6M2FkOjYwYjhdIMtq3Fwp-VUQC2W_EpT-VoRXmrNJnMl5jwDQG7XBqaLHGzIuZG5zY3J5cHQtY2VydC5leGFtcGxlLmNvbQ",
            dnsstamps.create_dnscrypt(address, public_key, provider_name),
            "Invalid stamp")

    def test_generate_dnscrypt_stamp_with_options(self):
        address = "127.0.0.1"
        public_key = "CB6A:DC5C:29F9:5510:0B65:BF12:94FE:5684:579A:B349:9CC9:798F:00D0:1BB5:C1A9:A2C7"
        provider_name = "2.dnscrypt-cert.example.com"
        options = [Option.DNSSEC, Option.NO_FILTERS]

        self.assertEqual(
            "sdns://AQUAAAAAAAAACTEyNy4wLjAuMSDLatxcKflVEAtlvxKU_laEV5qzSZzJeY8A0Bu1wamixxsyLmRuc2NyeXB0LWNlcnQuZXhhbXBsZS5jb20",
            dnsstamps.create_dnscrypt(address, public_key, provider_name, options),
            "Invalid stamp")

    def test_generate_doh_stamp(self):
        address = "[fe80::6d6d:f72c:3ad:60b8]"
        hashes = ["3e1a1a0f6c53f3e97a492d57084b5b9807059ee057ab1505876fd83fda3db838"]
        hostname = "doh.example.com"
        path = "/dns-query"

        self.assertEqual(
            "sdns://AgAAAAAAAAAAGltmZTgwOjo2ZDZkOmY3MmM6M2FkOjYwYjhdID4aGg9sU_PpekktVwhLW5gHBZ7gV6sVBYdv2D_aPbg4D2RvaC5leGFtcGxlLmNvbQovZG5zLXF1ZXJ5",
            dnsstamps.create_doh(address, hashes, hostname, path),
            "Invalid stamp")

    def test_generate_doh_stamp_with_options(self):
        address = "127.0.0.1"
        hashes = ["3e1a1a0f6c53f3e97a492d57084b5b9807059ee057ab1505876fd83fda3db838"]
        hostname = "doh.example.com"
        path = "/dns-query"
        options = [Option.NO_LOGS, Option.NO_FILTERS]

        self.assertEqual(
            "sdns://AgYAAAAAAAAACTEyNy4wLjAuMSA-GhoPbFPz6XpJLVcIS1uYBwWe4FerFQWHb9g_2j24OA9kb2guZXhhbXBsZS5jb20KL2Rucy1xdWVyeQ",
            dnsstamps.create_doh(address, hashes, hostname, path, options),
            "Invalid stamp")

    def test_generate_doh_stamp_with_multiple_hashes(self):
        address = "127.0.0.1"
        hashes = ["3e1a1a0f6c53f3e97a492d57084b5b9807059ee057ab1505876fd83fda3db838",
                  "d0b243776a6c10e4485b34ea3e3b3a063f3089770e04a78c8087b7c49d4f98d6"]
        hostname = "doh.example.com"
        path = "/dns-query"

        self.assertEqual(
            "sdns://AgAAAAAAAAAACTEyNy4wLjAuMaA-GhoPbFPz6XpJLVcIS1uYBwWe4FerFQWHb9g_2j24OCDQskN3amwQ5EhbNOo-OzoGPzCJdw4Ep4yAh7fEnU-Y1g9kb2guZXhhbXBsZS5jb20KL2Rucy1xdWVyeQ",
            dnsstamps.create_doh(address, hashes, hostname, path),
            "Invalid stamp")

    def test_generate_doh_stamp_with_bootstrap_ips(self):
        address = "127.0.0.1"
        hashes = ["3e1a1a0f6c53f3e97a492d57084b5b9807059ee057ab1505876fd83fda3db838"]
        hostname = "doh.example.com"
        path = "/dns-query"
        bootstrap_ips = ["1.1.1.1"]

        self.assertEqual(
            "sdns://AgAAAAAAAAAACTEyNy4wLjAuMSA-GhoPbFPz6XpJLVcIS1uYBwWe4FerFQWHb9g_2j24OA9kb2guZXhhbXBsZS5jb20KL2Rucy1xdWVyeQcxLjEuMS4x",
            dnsstamps.create_doh(address, hashes, hostname, path, bootstrap_ips=bootstrap_ips),
            "Invalid stamp")

    def test_generate_doh_stamp_without_hashes(self):
        address = ""
        hashes = []
        hostname = "doh.example.com"
        path = "/dns-query"
        options = [Option.DNSSEC, Option.NO_FILTERS]

        self.assertEqual(
            "sdns://AgUAAAAAAAAAAAAPZG9oLmV4YW1wbGUuY29tCi9kbnMtcXVlcnk",
            dnsstamps.create_doh(address, hashes, hostname, path, options),
            "Invalid stamp")

    def test_generate_dot_stamp(self):
        address = "[fe80::6d6d:f72c:3ad:60b8]"
        hashes = ["3e1a1a0f6c53f3e97a492d57084b5b9807059ee057ab1505876fd83fda3db838"]
        hostname = "dot.example.com"

        self.assertEqual(
            "sdns://AwAAAAAAAAAAGltmZTgwOjo2ZDZkOmY3MmM6M2FkOjYwYjhdID4aGg9sU_PpekktVwhLW5gHBZ7gV6sVBYdv2D_aPbg4D2RvdC5leGFtcGxlLmNvbQ",
            dnsstamps.create_dot(address, hashes, hostname),
            "Invalid stamp")

    def test_generate_dot_stamp_with_options(self):
        address = "127.0.0.1"
        hashes = ["3e1a1a0f6c53f3e97a492d57084b5b9807059ee057ab1505876fd83fda3db838"]
        hostname = "dot.example.com"
        options = [Option.DNSSEC]

        self.assertEqual(
            "sdns://AwEAAAAAAAAACTEyNy4wLjAuMSA-GhoPbFPz6XpJLVcIS1uYBwWe4FerFQWHb9g_2j24OA9kb3QuZXhhbXBsZS5jb20",
            dnsstamps.create_dot(address, hashes, hostname, options),
            "Invalid stamp")

    def test_generate_dot_stamp_with_multiple_hashes(self):
        address = "127.0.0.1"
        hashes = ["3e1a1a0f6c53f3e97a492d57084b5b9807059ee057ab1505876fd83fda3db838",
                  "d0b243776a6c10e4485b34ea3e3b3a063f3089770e04a78c8087b7c49d4f98d6"]
        hostname = "dot.example.com"

        self.assertEqual(
            "sdns://AwAAAAAAAAAACTEyNy4wLjAuMaA-GhoPbFPz6XpJLVcIS1uYBwWe4FerFQWHb9g_2j24OCDQskN3amwQ5EhbNOo-OzoGPzCJdw4Ep4yAh7fEnU-Y1g9kb3QuZXhhbXBsZS5jb20",
            dnsstamps.create_dot(address, hashes, hostname),
            "Invalid stamp")

    def test_generate_dot_stamp_with_bootstrap_ips(self):
        address = "127.0.0.1"
        hashes = ["3e1a1a0f6c53f3e97a492d57084b5b9807059ee057ab1505876fd83fda3db838"]
        hostname = "dot.example.com"
        bootstrap_ips = ["1.1.1.1"]

        self.assertEqual(
            "sdns://AwAAAAAAAAAACTEyNy4wLjAuMSA-GhoPbFPz6XpJLVcIS1uYBwWe4FerFQWHb9g_2j24OA9kb3QuZXhhbXBsZS5jb20HMS4xLjEuMQ",
            dnsstamps.create_dot(address, hashes, hostname, bootstrap_ips=bootstrap_ips),
            "Invalid stamp")

    def test_generate_dot_stamp_without_hashes(self):
        address = ""
        hashes = []
        hostname = "dot.example.com"
        options = [Option.DNSSEC, Option.NO_FILTERS]

        self.assertEqual(
            "sdns://AwUAAAAAAAAAAAAPZG90LmV4YW1wbGUuY29t",
            dnsstamps.create_dot(address, hashes, hostname, options),
            "Invalid stamp")

    def test_generate_doq_stamp(self):
        address = "[fe80::6d6d:f72c:3ad:60b8]"
        hashes = ["3e1a1a0f6c53f3e97a492d57084b5b9807059ee057ab1505876fd83fda3db838"]
        hostname = "doq.example.com"

        self.assertEqual(
            "sdns://BAAAAAAAAAAAGltmZTgwOjo2ZDZkOmY3MmM6M2FkOjYwYjhdID4aGg9sU_PpekktVwhLW5gHBZ7gV6sVBYdv2D_aPbg4D2RvcS5leGFtcGxlLmNvbQ",
            dnsstamps.create_doq(address, hashes, hostname),
            "Invalid stamp")

    def test_generate_doq_stamp_with_options(self):
        address = "127.0.0.1"
        hashes = ["3e1a1a0f6c53f3e97a492d57084b5b9807059ee057ab1505876fd83fda3db838"]
        hostname = "doq.example.com"
        options = [Option.DNSSEC]

        self.assertEqual(
            "sdns://BAEAAAAAAAAACTEyNy4wLjAuMSA-GhoPbFPz6XpJLVcIS1uYBwWe4FerFQWHb9g_2j24OA9kb3EuZXhhbXBsZS5jb20",
            dnsstamps.create_doq(address, hashes, hostname, options),
            "Invalid stamp")

    def test_generate_doq_stamp_with_multiple_hashes(self):
        address = "127.0.0.1"
        hashes = ["3e1a1a0f6c53f3e97a492d57084b5b9807059ee057ab1505876fd83fda3db838",
                  "d0b243776a6c10e4485b34ea3e3b3a063f3089770e04a78c8087b7c49d4f98d6"]
        hostname = "doq.example.com"

        self.assertEqual(
            "sdns://BAAAAAAAAAAACTEyNy4wLjAuMaA-GhoPbFPz6XpJLVcIS1uYBwWe4FerFQWHb9g_2j24OCDQskN3amwQ5EhbNOo-OzoGPzCJdw4Ep4yAh7fEnU-Y1g9kb3EuZXhhbXBsZS5jb20",
            dnsstamps.create_doq(address, hashes, hostname),
            "Invalid stamp")

    def test_generate_doq_stamp_with_bootstrap_ips(self):
        address = "127.0.0.1"
        hashes = ["3e1a1a0f6c53f3e97a492d57084b5b9807059ee057ab1505876fd83fda3db838"]
        hostname = "doq.example.com"
        bootstrap_ips = ["1.1.1.1"]

        self.assertEqual(
            "sdns://BAAAAAAAAAAACTEyNy4wLjAuMSA-GhoPbFPz6XpJLVcIS1uYBwWe4FerFQWHb9g_2j24OA9kb3EuZXhhbXBsZS5jb20HMS4xLjEuMQ",
            dnsstamps.create_doq(address, hashes, hostname, bootstrap_ips=bootstrap_ips),
            "Invalid stamp")

    def test_generate_doq_stamp_without_hashes(self):
        address = ""
        hashes = []
        hostname = "doq.example.com"
        options = [Option.DNSSEC, Option.NO_FILTERS]

        self.assertEqual(
            "sdns://BAUAAAAAAAAAAAAPZG9xLmV4YW1wbGUuY29t",
            dnsstamps.create_doq(address, hashes, hostname, options),
            "Invalid stamp")

    def test_generate_doh_target_stamp(self):
        hostname = "doh-target.example.com"
        path = "/dns-query"

        self.assertEqual(
            "sdns://BQAAAAAAAAAAFmRvaC10YXJnZXQuZXhhbXBsZS5jb20KL2Rucy1xdWVyeQ",
            dnsstamps.create_doh_target(hostname, path),
            "Invalid stamp")

    def test_generate_doh_target_stamp_with_options(self):
        hostname = "doh-target.example.com"
        path = "/dns-query"
        options = [Option.NO_LOGS, Option.NO_FILTERS]

        self.assertEqual(
            "sdns://BQYAAAAAAAAAFmRvaC10YXJnZXQuZXhhbXBsZS5jb20KL2Rucy1xdWVyeQ",
            dnsstamps.create_doh_target(hostname, path, options),
            "Invalid stamp")

    def test_generate_dnscrypt_relay_stamp(self):
        address = "127.0.0.1:443"
        self.assertEqual(
            "sdns://gQ0xMjcuMC4wLjE6NDQz",
            dnsstamps.create_dnscrypt_relay(address),
            "Invalid stamp")

    def test_generate_doh_relay_stamp(self):
        address = "[fe80::6d6d:f72c:3ad:60b8]"
        hashes = ["3e1a1a0f6c53f3e97a492d57084b5b9807059ee057ab1505876fd83fda3db838"]
        hostname = "doh-relay.example.com"
        path = "/dns-query"

        self.assertEqual(
            "sdns://hQAAAAAAAAAAGltmZTgwOjo2ZDZkOmY3MmM6M2FkOjYwYjhdID4aGg9sU_PpekktVwhLW5gHBZ7gV6sVBYdv2D_aPbg4FWRvaC1yZWxheS5leGFtcGxlLmNvbQovZG5zLXF1ZXJ5",
            dnsstamps.create_doh_relay(address, hashes, hostname, path),
            "Invalid stamp")

    def test_generate_doh_relay_stamp_with_options(self):
        address = "127.0.0.1"
        hashes = ["3e1a1a0f6c53f3e97a492d57084b5b9807059ee057ab1505876fd83fda3db838"]
        hostname = "doh-relay.example.com"
        path = "/dns-query"
        options = [Option.NO_LOGS]

        self.assertEqual(
            "sdns://hQIAAAAAAAAACTEyNy4wLjAuMSA-GhoPbFPz6XpJLVcIS1uYBwWe4FerFQWHb9g_2j24OBVkb2gtcmVsYXkuZXhhbXBsZS5jb20KL2Rucy1xdWVyeQ",
            dnsstamps.create_doh_relay(address, hashes, hostname, path, options),
            "Invalid stamp")

    def test_generate_doh_relay_stamp_with_multiple_hashes(self):
        address = "127.0.0.1"
        hashes = ["3e1a1a0f6c53f3e97a492d57084b5b9807059ee057ab1505876fd83fda3db838",
                  "d0b243776a6c10e4485b34ea3e3b3a063f3089770e04a78c8087b7c49d4f98d6"]
        hostname = "doh-relay.example.com"
        path = "/dns-query"

        self.assertEqual(
            "sdns://hQAAAAAAAAAACTEyNy4wLjAuMaA-GhoPbFPz6XpJLVcIS1uYBwWe4FerFQWHb9g_2j24OCDQskN3amwQ5EhbNOo-OzoGPzCJdw4Ep4yAh7fEnU-Y1hVkb2gtcmVsYXkuZXhhbXBsZS5jb20KL2Rucy1xdWVyeQ",
            dnsstamps.create_doh_relay(address, hashes, hostname, path),
            "Invalid stamp")

    def test_generate_doh_relay_stamp_with_bootstrap_ips(self):
        address = "127.0.0.1"
        hashes = ["3e1a1a0f6c53f3e97a492d57084b5b9807059ee057ab1505876fd83fda3db838"]
        hostname = "doh-relay.example.com"
        path = "/dns-query"
        bootstrap_ips = ["1.1.1.1"]

        self.assertEqual(
            "sdns://hQAAAAAAAAAACTEyNy4wLjAuMSA-GhoPbFPz6XpJLVcIS1uYBwWe4FerFQWHb9g_2j24OBVkb2gtcmVsYXkuZXhhbXBsZS5jb20KL2Rucy1xdWVyeQcxLjEuMS4x",
            dnsstamps.create_doh_relay(address, hashes, hostname, path, bootstrap_ips=bootstrap_ips),
            "Invalid stamp")

    def test_generate_doh_relay_stamp_without_hashes(self):
        address = ""
        hashes = []
        hostname = "doh-relay.example.com"
        path = "/dns-query"
        options = [Option.NO_LOGS]

        self.assertEqual(
            "sdns://hQIAAAAAAAAAAAAVZG9oLXJlbGF5LmV4YW1wbGUuY29tCi9kbnMtcXVlcnk",
            dnsstamps.create_doh_relay(address, hashes, hostname, path, options),
            "Invalid stamp")
