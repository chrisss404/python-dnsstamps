#!/usr/bin/env python


class State:

    def __init__(self):
        self._data = b''

    @property
    def data(self):
        return self._data

    @data.setter
    def data(self, data):
        self._data = data
