from enum import Enum


class Protocol(Enum):
    PLAIN = 0
    DNSCRYPT = 1
    DOH = 2
    DOT = 3
    DOQ = 4
    DOH_TARGET = 5
    DNSCRYPT_RELAY = 129
    DOH_RELAY = 133
