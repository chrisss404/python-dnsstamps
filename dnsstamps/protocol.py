from enum import Enum


class Protocol(Enum):
    PLAIN = 0
    DNSCRYPT = 1
    DOH = 2
    DOT = 3
