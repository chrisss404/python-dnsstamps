#!/usr/bin/env python

import base64
import binascii
import struct

from dnsstamps import Option
from dnsstamps import Parameter
from dnsstamps import Protocol


def pack_protocol(protocol):
    return struct.pack("<B", protocol.value)


def pack_options(options):
    props = 0
    if Option.DNSSEC in options:
        props |= 1
    if Option.NO_LOGS in options:
        props |= (1 << 1)
    if Option.NO_FILTERS in options:
        props |= (1 << 2)
    return struct.pack("<Q", props)


def pack_text_array(array):
    result = b''
    last_item = len(array) - 1
    for i, text in enumerate(array):
        result += pack_text(text, i != last_item)
    return result


def pack_text(text, set_high_bit=False):
    length = len(text)
    if set_high_bit:
        length |= (1 << 7)

    return struct.pack("<B", length) + text.encode('utf-8')


def pack_raw_array(array):
    result = b''
    last_item = len(array) - 1
    for i, raw in enumerate(array):
        result += pack_raw(raw, i != last_item)
    return result


def pack_raw(raw, set_high_bit=False):
    if isinstance(raw, str):
        raw = raw.replace(":", "").strip()
    binary = binascii.unhexlify(raw)

    length = len(binary)
    if set_high_bit:
        length |= (1 << 7)

    return struct.pack("<B", length) + binary


def create_stamp(payload):
    return "sdns://" + base64.urlsafe_b64encode(payload).decode("utf-8").rstrip("=")


def build_plain(parameter):
    return create_stamp(
        pack_protocol(parameter.protocol) +
        pack_options(parameter.options) +
        pack_text(parameter.address)
    )


def build_dnscrypt(parameter):
    return create_stamp(
        pack_protocol(parameter.protocol) +
        pack_options(parameter.options) +
        pack_text(parameter.address) +
        pack_raw(parameter.public_key) +
        pack_text(parameter.provider_name)
    )


def build_doh(parameter):
    if len(parameter.hashes) == 0:
        parameter.hashes.append("")

    return create_stamp(
        pack_protocol(parameter.protocol) +
        pack_options(parameter.options) +
        pack_text(parameter.address) +
        pack_raw_array(parameter.hashes) +
        pack_text(parameter.hostname) +
        pack_text(parameter.path) +
        pack_text_array(parameter.bootstrap_ips)
    )


def build_dot(parameter):
    if len(parameter.hashes) == 0:
        parameter.hashes.append("")

    return create_stamp(
        pack_protocol(parameter.protocol) +
        pack_options(parameter.options) +
        pack_text(parameter.address) +
        pack_raw_array(parameter.hashes) +
        pack_text(parameter.hostname) +
        pack_text_array(parameter.bootstrap_ips)
    )


def build(parameter):
    if not isinstance(parameter, Parameter):
        raise ValueError('Invalid parameter type %s' % type(parameter))

    if parameter.protocol == Protocol.PLAIN:
        return build_plain(parameter)
    elif parameter.protocol == Protocol.DNSCRYPT:
        return build_dnscrypt(parameter)
    elif parameter.protocol == Protocol.DOH:
        return build_doh(parameter)
    elif parameter.protocol == Protocol.DOT:
        return build_dot(parameter)


def prepare_plain(address, options=None):
    parameter = Parameter()
    parameter.protocol = Protocol.PLAIN

    if options is None:
        parameter.options = []
    else:
        parameter.options = options

    parameter.address = address
    return parameter


def prepare_dnscrypt(address, public_key, provider_name, options=None):
    parameter = Parameter()
    parameter.protocol = Protocol.DNSCRYPT

    if options is None:
        parameter.options = []
    else:
        parameter.options = options

    parameter.address = address
    parameter.public_key = public_key
    parameter.provider_name = provider_name
    return parameter


def prepare_doh(address, hashes, hostname, path, options=None, bootstrap_ips=None):
    parameter = Parameter()
    parameter.protocol = Protocol.DOH

    if options is None:
        parameter.options = []
    else:
        parameter.options = options

    parameter.address = address
    parameter.hashes = hashes
    parameter.hostname = hostname
    parameter.path = path

    if bootstrap_ips is None:
        parameter.bootstrap_ips = []
    else:
        parameter.bootstrap_ips = bootstrap_ips

    return parameter


def prepare_dot(address, hashes, hostname, options=None, bootstrap_ips=None):
    parameter = Parameter()
    parameter.protocol = Protocol.DOT

    if options is None:
        parameter.options = []
    else:
        parameter.options = options

    parameter.address = address
    parameter.hashes = hashes
    parameter.hostname = hostname

    if bootstrap_ips is None:
        parameter.bootstrap_ips = []
    else:
        parameter.bootstrap_ips = bootstrap_ips

    return parameter


def create_plain(address, options=None):
    return build(prepare_plain(address, options))


def create_dnscrypt(address, public_key, provider_name, options=None):
    return build(prepare_dnscrypt(address, public_key, provider_name, options))


def create_doh(address, hashes, hostname, path, options=None, bootstrap_ips=None):
    return build(prepare_doh(address, hashes, hostname, path, options, bootstrap_ips))


def create_dot(address, hashes, hostname, options=None, bootstrap_ips=None):
    return build(prepare_dot(address, hashes, hostname, options, bootstrap_ips))
