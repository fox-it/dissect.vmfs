class Error(Exception):
    pass


class VolumeUnavailable(Error):
    pass


class InvalidHeader(Error):
    pass


class FileNotFoundError(Error):
    pass


class NotADirectoryError(Error):
    pass


class NotASymlinkError(Error):
    pass
