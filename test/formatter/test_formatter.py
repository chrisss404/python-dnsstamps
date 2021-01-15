import unittest

import dnsstamps


class TestPrinter(unittest.TestCase):

    def test_format_with_invalid_parameter_type(self):
        with self.assertRaises(Exception) as context:
            dnsstamps.format(None)
        self.assertEqual(
            "Invalid parameter type <class 'NoneType'>",
            str(context.exception),
            "Invalid parameter type")

    def test_format_plain_stamp(self):
        address = "[fe80::6d6d:f72c:3ad:60b8]"
        parameter = dnsstamps.prepare_plain(address)
        dnsstamps.format(parameter)

    def test_format_dnscrypt_stamp(self):
        address = "[fe80::6d6d:f72c:3ad:60b8]"
        public_key = "CB6A:DC5C:29F9:5510:0B65:BF12:94FE:5684:579A:B349:9CC9:798F:00D0:1BB5:C1A9:A2C7"
        provider_name = "2.dnscrypt-cert.example.com"
        parameter = dnsstamps.prepare_dnscrypt(address, public_key, provider_name)
        dnsstamps.format(parameter)

    def test_format_doh_stamp(self):
        address = "[fe80::6d6d:f72c:3ad:60b8]"
        hashes = ["3e1a1a0f6c53f3e97a492d57084b5b9807059ee057ab1505876fd83fda3db838"]
        hostname = "doh.example.com"
        path = "/dns-query"
        parameter = dnsstamps.prepare_doh(address, hashes, hostname, path)
        dnsstamps.format(parameter)

    def test_format_dot_stamp(self):
        address = "[fe80::6d6d:f72c:3ad:60b8]"
        hashes = ["3e1a1a0f6c53f3e97a492d57084b5b9807059ee057ab1505876fd83fda3db838"]
        hostname = "dot.example.com"
        parameter = dnsstamps.prepare_dot(address, hashes, hostname)
        dnsstamps.format(parameter)

    def test_format_doq_stamp(self):
        address = "[fe80::6d6d:f72c:3ad:60b8]"
        hashes = ["3e1a1a0f6c53f3e97a492d57084b5b9807059ee057ab1505876fd83fda3db838"]
        hostname = "doq.example.com"
        parameter = dnsstamps.prepare_doq(address, hashes, hostname)
        dnsstamps.format(parameter)

    def test_format_doh_target_stamp(self):
        hostname = "doh-target.example.com"
        path = "/dns-query"
        parameter = dnsstamps.prepare_doh_target(hostname, path)
        dnsstamps.format(parameter)

    def test_format_dnscrypt_relay_stamp(self):
        address = "[fe80::6d6d:f72c:3ad:60b8]:433"
        parameter = dnsstamps.prepare_dnscrypt_relay(address)
        dnsstamps.format(parameter)

    def test_format_doh_relay_stamp(self):
        address = "[fe80::6d6d:f72c:3ad:60b8]"
        hashes = ["3e1a1a0f6c53f3e97a492d57084b5b9807059ee057ab1505876fd83fda3db838"]
        hostname = "doh-relay.example.com"
        path = "/dns-query"
        parameter = dnsstamps.prepare_doh_relay(address, hashes, hostname, path)
        dnsstamps.format(parameter)
