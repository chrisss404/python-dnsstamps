#!/usr/bin/env python

import base64
import binascii
import struct

from dnsstamps import Option


def pack_props(options):
    props = 0
    if Option.DNSSEC in options:
        props |= 1
    if Option.NO_LOGS in options:
        props |= (1 << 1)
    if Option.NO_BLOCKS in options:
        props |= (1 << 2)
    return props


def pack_text(text):
    return struct.pack("<B", len(text)) + text.encode('utf-8')


def pack_raw(raw):
    raw = raw.replace(":", "")
    binary = binascii.unhexlify(raw)
    return struct.pack("<B", len(binary)) + binary


def create_stamp(payload):
    return "sdns://" + base64.urlsafe_b64encode(payload).decode("utf-8").rstrip("=")


def plain(address, options=None):
    if options is None:
        options = []

    return create_stamp(
        struct.pack("<BQ", 0, pack_props(options)) +
        pack_text(address)
    )


def dnscrypt(address, public_key, provider_name, options=None):
    if options is None:
        options = []

    return create_stamp(
        struct.pack("<BQ", 1, pack_props(options)) +
        pack_text(address) +
        pack_raw(public_key) +
        pack_text(provider_name)
    )


def doh(address, hashes, hostname, path, options=None, bootstrap_ips=None):
    if options is None:
        options = []

    if bootstrap_ips is None:
        bootstrap_ips = []

    return create_stamp(
        struct.pack("<BQ", 2, pack_props(options)) +
        pack_text(address) +
        b''.join(map(pack_raw, hashes)) +
        pack_text(hostname) +
        pack_text(path) +
        b''.join(map(pack_text, bootstrap_ips))
    )


def dot(address, hashes, hostname, options=None, bootstrap_ips=None):
    if options is None:
        options = []

    if bootstrap_ips is None:
        bootstrap_ips = []

    return create_stamp(
        struct.pack("<BQ", 3, pack_props(options)) +
        pack_text(address) +
        b''.join(map(pack_raw, hashes)) +
        pack_text(hostname) +
        b''.join(map(pack_text, bootstrap_ips))
    )
