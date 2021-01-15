#!/usr/bin/env python

import argparse
import sys

import dnsstamps
from dnsstamps import Option


class DnsStampCli(object):

    @staticmethod
    def append_common_arguments(parser):
        parser.add_argument('-s', '--dnssec',
                            dest='dnssec',
                            action='store_true',
                            help="use if DNSSEC is supported (default: not supported)")
        parser.set_defaults(dnssec=False)

        parser.add_argument('-l', '--no-logs',
                            dest='logs',
                            action='store_true',
                            help="use if queries are not logged (default: are logged)")
        parser.set_defaults(logs=False)

        parser.add_argument('-f', '--no-filter',
                            dest='filter',
                            action='store_true',
                            help="use if domains are not filtered (default: are filtered)")
        parser.set_defaults(filter=False)

        parser.add_argument('-a', '--address',
                            type=str,
                            help="the ip address of the DNS server")

    def __init__(self):
        parser = argparse.ArgumentParser(usage='%(prog)s <command> [<args>]')
        parser.add_argument('command',
                            choices=['parse', 'plain', 'dnscrypt', 'doh', 'dot', 'doq', 'doh_target', 'dnscrypt_relay',
                                     'doh_relay'],
                            help='The command to execute.')

        args = parser.parse_args(sys.argv[1:2])
        getattr(self, args.command)()

    def parse(self):
        parser = argparse.ArgumentParser(description='Parse DNS stamp.')

        parser.add_argument('stamp', type=str, help='The stamp to parse.')

        args = parser.parse_args(sys.argv[2:])

        try:
            parameter = dnsstamps.parse(args.stamp)
            dnsstamps.format(parameter)
        except:
            print("Unable to parse DNS stamp <%s>" % args.stamp)

    def plain(self):
        parser = argparse.ArgumentParser(description='Create plain stamp')
        self.append_common_arguments(parser)

        args = parser.parse_args(sys.argv[2:])

        options = []
        if args.dnssec:
            options.append(Option.DNSSEC)
        if args.logs:
            options.append(Option.NO_LOGS)
        if args.filter:
            options.append(Option.NO_FILTERS)
        parameter = dnsstamps.prepare_plain("" if args.address is None else args.address, options)
        dnsstamps.format(parameter)

    def dnscrypt(self):
        parser = argparse.ArgumentParser(description='Create DNSCrypt stamp')
        self.append_common_arguments(parser)

        parser.add_argument('-k', '--public_key',
                            required=True,
                            type=str,
                            help="the DNSCrypt public key (e.g.: CB6A:DC5C:29F9:5510:0B65:BF12:94FE:5684:579A:B349:9CC9:798F:00D0:1BB5:C1A9:A2C7)")
        parser.add_argument('-n', '--provider_name',
                            required=True,
                            type=str,
                            help="the DNSCrypt provider name (e.g.: 2.dnscrypt-cert.example.com)")

        args = parser.parse_args(sys.argv[2:])

        options = []
        if args.dnssec:
            options.append(Option.DNSSEC)
        if args.logs:
            options.append(Option.NO_LOGS)
        if args.filter:
            options.append(Option.NO_FILTERS)
        parameter = dnsstamps.prepare_dnscrypt("" if args.address is None else args.address, args.public_key,
                                               args.provider_name, options)
        dnsstamps.format(parameter)

    def doh(self):
        parser = argparse.ArgumentParser(description='Create DNS-over-HTTPS stamp')
        self.append_common_arguments(parser)

        parser.add_argument('-t', '--hashes',
                            type=str,
                            help="a comma-separated list of tbs certificate hashes (e.g.: 3e1a1a0f6c53f3e97a492d57084b5b9807059ee057ab1505876fd83fda3db838)")
        parser.add_argument('-n', '--hostname',
                            required=True,
                            type=str,
                            help="the server hostname which will also be used as a SNI name (e.g.: doh.example.com)")
        parser.add_argument('-p', '--path',
                            required=True,
                            type=str,
                            help="the absolute URI path (e.g.: /dns-query)")
        parser.add_argument('-b', '--bootstrap_ips',
                            type=str,
                            help="a comma-separated list of bootstrap ips (e.g.: 1.1.1.1,1.0.0.1)")

        args = parser.parse_args(sys.argv[2:])

        options = []
        if args.dnssec:
            options.append(Option.DNSSEC)
        if args.logs:
            options.append(Option.NO_LOGS)
        if args.filter:
            options.append(Option.NO_FILTERS)
        parameter = dnsstamps.prepare_doh("" if args.address is None else args.address,
                                          [] if args.hashes is None else args.hashes.split(','), args.hostname,
                                          args.path, options,
                                          [] if args.bootstrap_ips is None else args.bootstrap_ips.split(','))
        dnsstamps.format(parameter)

    def dot(self):
        parser = argparse.ArgumentParser(description='Create DNS-over-TLS stamp')
        self.append_common_arguments(parser)

        parser.add_argument('-t', '--hashes',
                            type=str,
                            help="a comma-separated list of tbs certificate hashes (e.g.: 3e1a1a0f6c53f3e97a492d57084b5b9807059ee057ab1505876fd83fda3db838)")
        parser.add_argument('-n', '--hostname',
                            required=True,
                            type=str,
                            help="the server hostname which will also be used as a SNI name (e.g.: dot.example.com)")
        parser.add_argument('-b', '--bootstrap_ips',
                            type=str,
                            help="a comma-separated list of bootstrap ips (e.g.: 1.1.1.1,1.0.0.1)")

        args = parser.parse_args(sys.argv[2:])

        options = []
        if args.dnssec:
            options.append(Option.DNSSEC)
        if args.logs:
            options.append(Option.NO_LOGS)
        if args.filter:
            options.append(Option.NO_FILTERS)
        parameter = dnsstamps.prepare_dot("" if args.address is None else args.address,
                                          [] if args.hashes is None else args.hashes.split(','), args.hostname, options,
                                          [] if args.bootstrap_ips is None else args.bootstrap_ips.split(','))
        dnsstamps.format(parameter)

    def doq(self):
        parser = argparse.ArgumentParser(description='Create DNS-over-QUIC stamp')
        self.append_common_arguments(parser)

        parser.add_argument('-t', '--hashes',
                            type=str,
                            help="a comma-separated list of tbs certificate hashes (e.g.: 3e1a1a0f6c53f3e97a492d57084b5b9807059ee057ab1505876fd83fda3db838)")
        parser.add_argument('-n', '--hostname',
                            required=True,
                            type=str,
                            help="the server hostname which will also be used as a SNI name (e.g.: doq.example.com)")
        parser.add_argument('-b', '--bootstrap_ips',
                            type=str,
                            help="a comma-separated list of bootstrap ips (e.g.: 1.1.1.1,1.0.0.1)")

        args = parser.parse_args(sys.argv[2:])

        options = []
        if args.dnssec:
            options.append(Option.DNSSEC)
        if args.logs:
            options.append(Option.NO_LOGS)
        if args.filter:
            options.append(Option.NO_FILTERS)
        parameter = dnsstamps.prepare_doq("" if args.address is None else args.address,
                                          [] if args.hashes is None else args.hashes.split(','), args.hostname, options,
                                          [] if args.bootstrap_ips is None else args.bootstrap_ips.split(','))
        dnsstamps.format(parameter)

    def doh_target(self):
        parser = argparse.ArgumentParser(description='Create DoH target stamp')
        self.append_common_arguments(parser)

        parser.add_argument('-n', '--hostname',
                            required=True,
                            type=str,
                            help="the server hostname which will also be used as a SNI name (e.g.: doh-target.example.com)")
        parser.add_argument('-p', '--path',
                            required=True,
                            type=str,
                            help="the absolute URI path (e.g.: /dns-query)")

        args = parser.parse_args(sys.argv[2:])

        options = []
        if args.dnssec:
            options.append(Option.DNSSEC)
        if args.logs:
            options.append(Option.NO_LOGS)
        if args.filter:
            options.append(Option.NO_FILTERS)
        parameter = dnsstamps.prepare_doh_target(args.hostname, args.path, options)
        dnsstamps.format(parameter)

    def dnscrypt_relay(self):
        parser = argparse.ArgumentParser(description='Create DNSCrypt relay stamp')
        self.append_common_arguments(parser)

        args = parser.parse_args(sys.argv[2:])

        parameter = dnsstamps.prepare_dnscrypt_relay("" if args.address is None else args.address)
        dnsstamps.format(parameter)

    def doh_relay(self):
        parser = argparse.ArgumentParser(description='Create DoH relay stamp')
        self.append_common_arguments(parser)

        parser.add_argument('-t', '--hashes',
                            type=str,
                            help="a comma-separated list of tbs certificate hashes (e.g.: 3e1a1a0f6c53f3e97a492d57084b5b9807059ee057ab1505876fd83fda3db838)")
        parser.add_argument('-n', '--hostname',
                            required=True,
                            type=str,
                            help="the server hostname which will also be used as a SNI name (e.g.: doh-relay.example.com)")
        parser.add_argument('-p', '--path',
                            required=True,
                            type=str,
                            help="the absolute URI path (e.g.: /dns-query)")
        parser.add_argument('-b', '--bootstrap_ips',
                            type=str,
                            help="a comma-separated list of bootstrap ips (e.g.: 1.1.1.1,1.0.0.1)")

        args = parser.parse_args(sys.argv[2:])

        options = []
        if args.dnssec:
            options.append(Option.DNSSEC)
        if args.logs:
            options.append(Option.NO_LOGS)
        if args.filter:
            options.append(Option.NO_FILTERS)
        parameter = dnsstamps.prepare_doh_relay("" if args.address is None else args.address,
                                                [] if args.hashes is None else args.hashes.split(','), args.hostname,
                                                args.path, options,
                                                [] if args.bootstrap_ips is None else args.bootstrap_ips.split(','))
        dnsstamps.format(parameter)


if __name__ == '__main__':
    DnsStampCli()
