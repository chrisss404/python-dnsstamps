#!/usr/bin/env python

import base64
import binascii
import struct

from dnsstamps import Option
from dnsstamps import Parameter
from dnsstamps import Protocol
from dnsstamps.parser.state import State


def create_state_for_stamp(stamp):
    try:
        state = State()
        state.data = base64.urlsafe_b64decode(stamp.replace('sdns://', '') + '===')
        return state
    except Exception as e:
        raise Exception('Unable to unpack stamp', e)


def consume_protocol(state):
    try:
        raw_protocol = struct.unpack('<B', state.data[:1])[0]
        state.data = state.data[1:]
        return Protocol(raw_protocol)
    except Exception as e:
        raise Exception('Unable to consume protocol', e)


def consume_options(state):
    try:
        raw_options = struct.unpack('<Q', state.data[:8])[0]

        options = []
        if raw_options & 1:
            options.append(Option.DNSSEC)
        if raw_options & (1 << 1):
            options.append(Option.NO_LOGS)
        if raw_options & (1 << 2):
            options.append(Option.NO_FILTERS)

        state.data = state.data[8:]
        return options
    except Exception as e:
        raise Exception('Unable to consume options', e)


def consume_text(state):
    try:
        length = struct.unpack('<B', state.data[:1])[0]
        text = state.data[1:length + 1].decode('utf-8')
        state.data = state.data[length + 1:]
        return text
    except Exception as e:
        raise Exception('Unable to consume text', e)


def consume_text_array(state):
    items = []
    while len(state.data) > 0:
        item = consume_text(state)
        if item is None:
            break
        items.append(item)
    return items


def consume_raw(state):
    try:
        length = struct.unpack('<B', state.data[:1])[0]

        if length == 0:
            state.data = state.data[1:]
            return None

        # unset high bit
        length &= ~(1 << 7)

        bytes = state.data[1:length + 1]
        try:
            bytes.decode('utf-8')
            return None
        except:
            state.data = state.data[length + 1:]
            return binascii.hexlify(bytes)
    except Exception as e:
        raise Exception('Unable to consume raw', e)


def consume_raw_array(state):
    items = []

    done = False
    while not done:
        length = struct.unpack('<B', state.data[:1])[0]
        done = not (length & (1 << 7))

        item = consume_raw(state)
        if item is None:
            break
        items.append(item)
    return items


def parse_plain(state, parameter):
    parameter.options = consume_options(state)
    parameter.address = consume_text(state)


def parse_dnscrypt(state, parameter):
    parameter.options = consume_options(state)
    parameter.address = consume_text(state)
    parameter.public_key = consume_raw(state)
    parameter.provider_name = consume_text(state)


def parse_doh(state, parameter):
    parameter.options = consume_options(state)
    parameter.address = consume_text(state)
    parameter.hashes = consume_raw_array(state)
    parameter.hostname = consume_text(state)
    parameter.path = consume_text(state)
    parameter.bootstrap_ips = consume_text_array(state)


def parse_dot(state, parameter):
    parameter.options = consume_options(state)
    parameter.address = consume_text(state)
    parameter.hashes = consume_raw_array(state)
    parameter.hostname = consume_text(state)
    parameter.bootstrap_ips = consume_text_array(state)


def parse(stamp):
    parameter = Parameter()

    state = create_state_for_stamp(stamp)
    parameter.protocol = consume_protocol(state)

    if parameter.protocol == Protocol.PLAIN:
        parse_plain(state, parameter)
    elif parameter.protocol == Protocol.DNSCRYPT:
        parse_dnscrypt(state, parameter)
    elif parameter.protocol == Protocol.DOH:
        parse_doh(state, parameter)
    elif parameter.protocol == Protocol.DOT:
        parse_dot(state, parameter)

    return parameter
