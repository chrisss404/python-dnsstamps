#!/usr/bin/env python

from dnsstamps import Option
from dnsstamps import Parameter
from dnsstamps import Protocol
from dnsstamps import build


def print_options(parameter):
    print('DNSSEC: %s' % ('yes' if Option.DNSSEC in parameter.options else 'no'))
    print('No logs: %s' % ('yes' if Option.NO_LOGS in parameter.options else 'no'))
    print('No filter: %s' % ('yes' if Option.NO_FILTERS in parameter.options else 'no'))


def print_plain(parameter):
    print('Plain DNS stamp')
    print('===============')
    print('')
    print_options(parameter)
    print('IP Address: %s' % parameter.address)
    print('')
    print(build(parameter))


def print_dnscrypt(parameter):
    print('DNSCrypt DNS stamp')
    print('==================')
    print('')
    print_options(parameter)
    print('IP Address: %s' % parameter.address)
    print('Public key: %s' % parameter.public_key)
    print('Provider name: %s' % parameter.provider_name)
    print('')
    print(build(parameter))


def print_doh(parameter):
    print('DoH DNS stamp')
    print('=============')
    print('')
    print_options(parameter)
    print('IP Address: %s' % parameter.address)
    print('Hashes: %s' % parameter.hashes)
    print('Hostname: %s' % parameter.hostname)
    print('Path: %s' % parameter.path)
    print('Bootstrap IPs: %s' % parameter.bootstrap_ips)
    print('')
    print(build(parameter))


def print_dot(parameter):
    print('DoT DNS stamp')
    print('=============')
    print('')
    print_options(parameter)
    print('IP Address: %s' % parameter.address)
    print('Hostname: %s' % parameter.hostname)
    print('Hashes: %s' % parameter.hashes)
    print('Bootstrap IPs: %s' % parameter.bootstrap_ips)
    print('')
    print(build(parameter))


def print_doq(parameter):
    print('DoQ DNS stamp')
    print('=============')
    print('')
    print_options(parameter)
    print('IP Address: %s' % parameter.address)
    print('Hostname: %s' % parameter.hostname)
    print('Hashes: %s' % parameter.hashes)
    print('Bootstrap IPs: %s' % parameter.bootstrap_ips)
    print('')
    print(build(parameter))


def print_doh_target(parameter):
    print('DoH Target DNS stamp')
    print('====================')
    print('')
    print_options(parameter)
    print('Hostname: %s' % parameter.hostname)
    print('Path: %s' % parameter.path)
    print('')
    print(build(parameter))


def print_dnscrypt_relay(parameter):
    print('DNSCrypt DNS Relay Stamp')
    print('========================')
    print('')
    print('IP Address: %s' % parameter.address)
    print('')
    print(build(parameter))


def print_doh_relay(parameter):
    print('DoH Relay DNS stamp')
    print('===================')
    print('')
    print_options(parameter)
    print('IP Address: %s' % parameter.address)
    print('Hashes: %s' % parameter.hashes)
    print('Hostname: %s' % parameter.hostname)
    print('Path: %s' % parameter.path)
    print('Bootstrap IPs: %s' % parameter.bootstrap_ips)
    print('')
    print(build(parameter))


def format(parameter):
    if not isinstance(parameter, Parameter):
        raise ValueError('Invalid parameter type %s' % type(parameter))

    if parameter.protocol == Protocol.PLAIN:
        return print_plain(parameter)
    elif parameter.protocol == Protocol.DNSCRYPT:
        return print_dnscrypt(parameter)
    elif parameter.protocol == Protocol.DOH:
        return print_doh(parameter)
    elif parameter.protocol == Protocol.DOT:
        return print_dot(parameter)
    elif parameter.protocol == Protocol.DOQ:
        return print_doq(parameter)
    elif parameter.protocol == Protocol.DOH_TARGET:
        return print_doh_target(parameter)
    elif parameter.protocol == Protocol.DNSCRYPT_RELAY:
        return print_dnscrypt_relay(parameter)
    elif parameter.protocol == Protocol.DOH_RELAY:
        return print_doh_relay(parameter)
