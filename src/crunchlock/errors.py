class CrunchlockError(Exception):
    """Base error for all crunchlock failures."""


class WrongKeyError(CrunchlockError):
    """The password / keyfile / private key does not open this file."""


class CorruptFileError(CrunchlockError):
    """The file is damaged, truncated or has been tampered with."""
