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
                            required=True,
                            type=str,
                            help="the ip address of the DNS server")

    def __init__(self):
        parser = argparse.ArgumentParser(usage='%(prog)s <protocol> [<args>]')
        parser.add_argument('protocol',
                            choices=['plain', 'dnscrypt', 'doh', 'dot'],
                            help='The protocol used by the DNS server')

        args = parser.parse_args(sys.argv[1:2])
        getattr(self, args.protocol)()

    def plain(self):
        parser = argparse.ArgumentParser(description='Create plain stamp')
        self.append_common_arguments(parser)

        args = parser.parse_args(sys.argv[2:])

        options = [Option.DNSSEC, Option.NO_LOGS, Option.NO_BLOCKS]
        if args.dnssec:
            options.append(Option.DNSSEC)
        if args.logs:
            options.append(Option.NO_LOGS)
        if args.filter:
            options.append(Option.NO_BLOCKS)
        stamp = dnsstamps.plain(args.address, options)

        print('Plain DNS stamp')
        print('==================')
        print('')
        print('DNSSEC: %s' % ('yes' if args.dnssec else 'no'))
        print('No logs: %s' % ('yes' if args.logs else 'no'))
        print('No filter: %s' % ('yes' if args.filter else 'no'))
        print('IP Address: %s' % args.address)
        print('')
        print('Stamp: %s' % stamp)

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

        options = [Option.DNSSEC, Option.NO_LOGS, Option.NO_BLOCKS]
        if args.dnssec:
            options.append(Option.DNSSEC)
        if args.logs:
            options.append(Option.NO_LOGS)
        if args.filter:
            options.append(Option.NO_BLOCKS)
        stamp = dnsstamps.dnscrypt(args.address, args.public_key, args.provider_name, options)

        print('DNSCrypt DNS stamp')
        print('==================')
        print('')
        print('DNSSEC: %s' % ('yes' if args.dnssec else 'no'))
        print('No logs: %s' % ('yes' if args.logs else 'no'))
        print('No filter: %s' % ('yes' if args.filter else 'no'))
        print('IP Address: %s' % args.address)
        print('Public key: %s' % args.public_key)
        print('Provider name: %s' % args.provider_name)
        print('')
        print('Stamp: %s' % stamp)

    def doh(self):
        parser = argparse.ArgumentParser(description='Create DNS over HTTPS stamp')
        self.append_common_arguments(parser)

        parser.add_argument('-t', '--hashes',
                            required=True,
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

        options = [Option.DNSSEC, Option.NO_LOGS, Option.NO_BLOCKS]
        if args.dnssec:
            options.append(Option.DNSSEC)
        if args.logs:
            options.append(Option.NO_LOGS)
        if args.filter:
            options.append(Option.NO_BLOCKS)
        stamp = dnsstamps.doh(args.address, args.hashes.split(','), args.hostname, args.path, options,
                              [] if args.bootstrap_ips is None else args.bootstrap_ips.split(','))

        print('DoH DNS stamp')
        print('=============')
        print('')
        print('DNSSEC: %s' % ('yes' if args.dnssec else 'no'))
        print('No logs: %s' % ('yes' if args.logs else 'no'))
        print('No filter: %s' % ('yes' if args.filter else 'no'))
        print('IP Address: %s' % args.address)
        print('Hashes: %s' % args.hashes)
        print('Hostname: %s' % args.hostname)
        print('Path: %s' % args.path)
        print('Bootstrap IPs: %s' % args.bootstrap_ips)
        print('')
        print('Stamp: %s' % stamp)

    def dot(self):
        parser = argparse.ArgumentParser(description='Create DNS over TLS stamp')
        self.append_common_arguments(parser)

        parser.add_argument('-t', '--hashes',
                            required=True,
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

        options = [Option.DNSSEC, Option.NO_LOGS, Option.NO_BLOCKS]
        if args.dnssec:
            options.append(Option.DNSSEC)
        if args.logs:
            options.append(Option.NO_LOGS)
        if args.filter:
            options.append(Option.NO_BLOCKS)
        stamp = dnsstamps.dot(args.address, args.hashes.split(','), args.hostname, options,
                              [] if args.bootstrap_ips is None else args.bootstrap_ips.split(','))

        print('DoT DNS stamp')
        print('=============')
        print('')
        print('DNSSEC: %s' % ('yes' if args.dnssec else 'no'))
        print('No logs: %s' % ('yes' if args.logs else 'no'))
        print('No filter: %s' % ('yes' if args.filter else 'no'))
        print('IP Address: %s' % args.address)
        print('Hostname: %s' % args.hostname)
        print('Hashes: %s' % args.hashes)
        print('Bootstrap IPs: %s' % args.bootstrap_ips)
        print('')
        print('Stamp: %s' % stamp)


if __name__ == '__main__':
    DnsStampCli()
