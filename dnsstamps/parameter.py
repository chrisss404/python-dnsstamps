from dnsstamps import Protocol


class Parameter:

    def __init__(self):
        self._protocol = Protocol.PLAIN
        self._options = []
        self._address = '127.0.0.1'
        self._public_key = b''
        self._provider_name = ''
        self._hashes = []
        self._hostname = ''
        self._path = ''
        self._bootstrap_ips = []

    @property
    def protocol(self):
        return self._protocol

    @protocol.setter
    def protocol(self, protocol):
        if isinstance(protocol, Protocol):
            self._protocol = protocol
        else:
            raise ValueError('Unrecognized protocol <%s>' % protocol)

    @property
    def options(self):
        return self._options

    @options.setter
    def options(self, options):
        self._options = options

    @property
    def address(self):
        return self._address

    @address.setter
    def address(self, address):
        self._address = address

    @property
    def public_key(self):
        return self._public_key

    @public_key.setter
    def public_key(self, public_key):
        self._public_key = public_key

    @property
    def provider_name(self):
        return self._provider_name

    @provider_name.setter
    def provider_name(self, provider_name):
        self._provider_name = provider_name

    @property
    def hashes(self):
        return self._hashes

    @hashes.setter
    def hashes(self, hashes):
        self._hashes = hashes

    @property
    def hostname(self):
        return self._hostname

    @hostname.setter
    def hostname(self, hostname):
        self._hostname = hostname

    @property
    def path(self):
        return self._path

    @path.setter
    def path(self, path):
        self._path = path

    @property
    def bootstrap_ips(self):
        return self._bootstrap_ips

    @bootstrap_ips.setter
    def bootstrap_ips(self, bootstrap_ips):
        self._bootstrap_ips = bootstrap_ips
